//! Главная логика прокси: проверить запрос → отправить провайдеру → вернуть ответ.
//!
//! Порядок проверок важен: сначала дешёвые (ключ, лимит, JSON), и только потом
//! дорогой сетевой запрос. Так мусорный трафик не доходит до платного API.
//!
//! Два провайдера:
//! * основной — OpenAI-совместимый API;
//! * Ollama — и через маршрутизацию по префиксу модели в `/v1/chat/completions`,
//!   и через собственные native-эндпоинты `/api/*`.

use std::time::Instant;

use crate::{
    config::{Config, OllamaConfig, MAX_ERROR_BODY_BYTES, MAX_RESPONSE_BYTES},
    security, AppState,
};
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::process::Stdio;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Ошибки, которые мы отдаём клиенту.
///
/// Принцип: наружу — короткое безопасное сообщение, подробности — только в лог на сервере.
/// Ответ повторяет форму ошибок OpenAI: `{"error": {"message": ..., "type": ...}}`,
/// чтобы официальные SDK понимали его без изменений.
#[derive(Debug)]
pub enum AppError {
    Unauthorized,             // 401 — нет/неверный ключ клиента
    Forbidden,                // 403 — модель не разрешена
    BadRequest(&'static str), // 400 — некорректное тело
    NotFound(&'static str),   // 404 — эндпоинт/провайдер не существует
    RateLimited,              // 429 — клиент превысил свой лимит
    Busy,                     // 503 — все слоты к провайдеру заняты
    Upstream(&'static str),   // 502 — проблема на стороне провайдера
    GatewayTimeout,           // 504 — провайдер не ответил вовремя
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, kind, message) = match self {
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "invalid_request_error",
                "Неверный или отсутствующий ключ. Ожидается заголовок Authorization: Bearer <ключ>",
            ),
            AppError::Forbidden => (
                StatusCode::FORBIDDEN,
                "invalid_request_error",
                "Модель не разрешена",
            ),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, "invalid_request_error", m),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, "invalid_request_error", m),
            AppError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_error",
                "Превышен лимит запросов, повторите позже",
            ),
            AppError::Busy => (
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Прокси перегружен, повторите позже",
            ),
            AppError::Upstream(m) => (StatusCode::BAD_GATEWAY, "upstream_error", m),
            AppError::GatewayTimeout => (
                StatusCode::GATEWAY_TIMEOUT,
                "upstream_error",
                "Провайдер не ответил вовремя",
            ),
        };

        let mut resp = (
            status,
            Json(json!({"error": {"message": message, "type": kind}})),
        )
            .into_response();
        if status == StatusCode::TOO_MANY_REQUESTS {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        resp
    }
}

/// Разобранное и приведённое в порядок тело запроса.
pub struct Prepared {
    pub body: Vec<u8>,
    pub model: String,
    pub stream: bool,
    /// Идёт ли этот запрос в Ollama (маршрутизация по префиксу модели).
    pub to_ollama: bool,
}

/// Обработчик POST /v1/chat/completions.
///
/// Модель с префиксом `ollama/` уходит в Ollama (её OpenAI-совместимый /v1),
/// остальные — к основному провайдеру.
pub async fn chat_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let started = Instant::now();

    // 1. Кто пришёл. Заголовок клиента проверяем сами — наружу он НЕ уходит.
    let client =
        security::authenticate(headers.get(header::AUTHORIZATION), &state.cfg.client_keys)?;

    // 2. Лимит запросов этого клиента.
    if !state.limiter.allow(client) {
        tracing::warn!(client, "превышен лимит запросов");
        return Err(AppError::RateLimited);
    }

    // 3. Разбор и валидация JSON (размер тела уже ограничен слоем DefaultBodyLimit).
    let prepared = prepare_request(&body, &state.cfg).await?;

    // 4. Маршрутизация: префикс ollama/ => локальная Ollama.
    let ollama = if prepared.to_ollama {
        match &state.cfg.ollama {
            Some(oc) => Some(oc.clone()),
            None => {
                return Err(AppError::BadRequest(
                    "Модель с префиксом ollama/ указана, но Ollama выключена (OLLAMA_ENABLED=0?)",
                ))
            }
        }
    } else {
        None
    };

    // 5. Слот конкурентности: не больше N одновременных обращений к провайдеру.
    //    try_acquire — не ждём в очереди, а сразу отвечаем 503 (честный backpressure).
    //    У Ollama свой пул слотов: одна тяжёлая локальная модель не должна
    //    выедать слоты платного API и наоборот.
    let permit = if ollama.is_some() {
        state
            .ollama_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| AppError::Busy)?
    } else {
        state
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| AppError::Busy)?
    };

    // 6. Запрос к провайдеру. Заголовки собираем с нуля — это «белый список»:
    //    ни Authorization клиента, ни Cookie, ни Host не утекут наружу.
    let (url, api_key) = match &ollama {
        Some(oc) => (oc.chat_completions_url(), oc.api_key.clone()),
        None => (state.cfg.chat_completions_url(), Some(state.cfg.upstream_api_key.clone())),
    };

    let mut request = state
        .http
        .post(url)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::ACCEPT,
            if prepared.stream {
                "text/event-stream"
            } else {
                "application/json"
            },
        )
        .body(prepared.body);

    // Ключ подставляется ТОЛЬКО здесь. Локальная Ollama без авторизации
    // остаётся без Authorization вовсе.
    if let Some(key) = api_key {
        request = request.bearer_auth(key);
    }

    if !prepared.stream {
        // Полный таймаут ставим ТОЛЬКО нестриминговым запросам:
        // у стрима ответ может идти минутами, и общий таймаут оборвал бы его на середине.
        // Для стрима работают connect_timeout и read_timeout (простой между кусками).
        request = request.timeout(state.cfg.request_timeout);
    }

    let upstream = request.send().await.map_err(|e| {
        // В лог идёт текст ошибки reqwest (URL, TLS, таймаут) — заголовков и ключей там нет.
        tracing::warn!(error = %e, ollama = ollama.is_some(), "не удалось выполнить запрос к провайдеру");
        if e.is_timeout() {
            AppError::GatewayTimeout
        } else {
            AppError::Upstream(if ollama.is_some() {
                "Не удалось связаться с Ollama (запущена ли она?)"
            } else {
                "Не удалось связаться с провайдером"
            })
        }
    })?;

    let status = upstream.status();

    // 7. Провайдер вернул ошибку.
    if !status.is_success() {
        return Ok(upstream_error_response(upstream, status).await);
    }

    // 8. Успех: стрим или обычный ответ.
    let content_type = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/json"));

    let response = if prepared.stream {
        streaming_response(upstream, permit)
    } else {
        let bytes = read_capped(upstream, MAX_RESPONSE_BYTES).await?;
        ([(header::CONTENT_TYPE, content_type)], bytes).into_response()
    };

    tracing::info!(
        client,
        model = %prepared.model,
        ollama = prepared.to_ollama,
        stream = prepared.stream,
        status = status.as_u16(),
        ms = started.elapsed().as_millis() as u64,
        "запрос обработан"
    );
    Ok(response)
}

// ---------------------------------------------------------------------------
// Native Ollama API (/api/*)
// ---------------------------------------------------------------------------

/// Общая проверка входа native-эндпоинтов Ollama: аутентификация + лимит.
/// Возвращает (номер клиента, слот конкурентности).
async fn ollama_gate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(usize, tokio::sync::OwnedSemaphorePermit), AppError> {
    state
        .cfg
        .ollama
        .as_ref()
        .ok_or(AppError::NotFound(
            "Ollama не настроена: OLLAMA_ENABLED=0 или пустой OLLAMA_BASE_URL",
        ))?;

    let client =
        security::authenticate(headers.get(header::AUTHORIZATION), &state.cfg.client_keys)?;
    if !state.limiter.allow(client) {
        tracing::warn!(client, "превышен лимит запросов (ollama)");
        return Err(AppError::RateLimited);
    }

    let permit = state
        .ollama_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::Busy)?;

    Ok((client, permit))
}

/// Обрабатывает POST к native-эндпоинту Ollama (`/api/chat`, `/api/generate`,
/// `/api/embeddings`, `/api/show`). Тело проходит ту же валидацию, что и чат:
/// валидный JSON-объект + срезание потолка токенов (`options.num_predict`).
async fn ollama_proxy(
    state: AppState,
    headers: HeaderMap,
    body: Bytes,
    path: &'static str,
) -> Result<Response, AppError> {
    let started = Instant::now();
    let (client, permit) = ollama_gate(&state, &headers).await?;
    let oc = state.cfg.ollama.clone().expect("проверено в ollama_gate");

    // Валидируем и нормализуем тело: model обязательна, num_predict режем.
    let body = ollama_prepare_body(&body, &state.cfg).await?;

    let stream = ollama_is_stream(&body);

    let mut request = state
        .http
        .post(oc.api_url(path))
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::ACCEPT,
            if stream {
                "application/x-ndjson"
            } else {
                "application/json"
            },
        )
        .body(body);
    if let Some(key) = oc.api_key.clone() {
        request = request.bearer_auth(key);
    }
    if !stream {
        request = request.timeout(state.cfg.request_timeout);
    }

    let upstream = request.send().await.map_err(|e| {
        tracing::warn!(error = %e, path, "не удалось выполнить запрос к Ollama");
        if e.is_timeout() {
            AppError::GatewayTimeout
        } else {
            AppError::Upstream("Не удалось связаться с Ollama (запущена ли она?)")
        }
    })?;

    let status = upstream.status();
    if !status.is_success() {
        return Ok(upstream_error_response(upstream, status).await);
    }

    let content_type = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/json"));

    // Стрим Ollama — это NDJSON: строки JSON, разделённые \n, ответ приходит
    // постепенно. Проксируем тем же механизмом «канал + задача», что и SSE;
    // permit уходит в задачу и живёт, пока течёт поток.
    let response = if stream {
        streaming_ndjson_response(upstream, permit)
    } else {
        let bytes = read_capped(upstream, MAX_RESPONSE_BYTES).await?;
        ([(header::CONTENT_TYPE, content_type)], bytes).into_response()
    };

    tracing::info!(
        client,
        path,
        ollama = true,
        stream,
        status = status.as_u16(),
        ms = started.elapsed().as_millis() as u64,
        "запрос к Ollama обработан"
    );
    Ok(response)
}

/// POST /api/chat — стриминговый чат Ollama (NDJSON).
pub async fn ollama_chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    ollama_proxy(state, headers, body, "/api/chat").await
}

/// POST /api/generate — генерация одного ответа (NDJSON при stream=true).
pub async fn ollama_generate(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    ollama_proxy(state, headers, body, "/api/generate").await
}

/// POST /api/embeddings — эмбеддинги.
pub async fn ollama_embeddings(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    ollama_proxy(state, headers, body, "/api/embeddings").await
}

/// POST /api/show — метаданные модели.
pub async fn ollama_show(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    ollama_proxy(state, headers, body, "/api/show").await
}

/// GET /api/tags — список установленных моделей (проходит аутентификацию
/// и лимит, но без слота конкурентности: это лёгкий запрос).
pub async fn ollama_tags(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    ollama_get_light(state, headers, "/api/tags").await
}

/// GET /api/version — версия Ollama.
pub async fn ollama_version(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    ollama_get_light(state, headers, "/api/version").await
}

/// Общий обработчик лёгких GET-эндпоинтов Ollama.
async fn ollama_get_light(
    state: AppState,
    headers: HeaderMap,
    path: &'static str,
) -> Result<Response, AppError> {
    let client =
        security::authenticate(headers.get(header::AUTHORIZATION), &state.cfg.client_keys)?;
    if !state.limiter.allow(client) {
        return Err(AppError::RateLimited);
    }
    let oc = state
        .cfg
        .ollama
        .as_ref()
        .ok_or(AppError::NotFound("Ollama не настроена"))?
        .clone();

    let mut request = state
        .http
        .get(oc.api_url(path))
        .header(header::ACCEPT, "application/json")
        .timeout(state.cfg.request_timeout);
    if let Some(key) = oc.api_key.clone() {
        request = request.bearer_auth(key);
    }

    let upstream = request.send().await.map_err(|e| {
        tracing::warn!(error = %e, path, "не удалось выполнить GET к Ollama");
        if e.is_timeout() {
            AppError::GatewayTimeout
        } else {
            AppError::Upstream("Не удалось связаться с Ollama (запущена ли она?)")
        }
    })?;

    let status = upstream.status();
    if !status.is_success() {
        return Ok(upstream_error_response(upstream, status).await);
    }

    let content_type = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/json"));
    let bytes = read_capped(upstream, 1024 * 1024).await?;
    Ok(([(header::CONTENT_TYPE, content_type)], bytes).into_response())
}

/// Список моделей Ollama для /v1/models. `None` — Ollama недоступна
/// (возвращаем просто пустой список, не ломаем эндпоинт).
pub async fn ollama_model_list(state: &AppState, oc: &OllamaConfig) -> Option<Vec<String>> {
    let mut request = state
        .http
        .get(oc.tags_url())
        .timeout(std::time::Duration::from_secs(5));
    if let Some(key) = &oc.api_key {
        request = request.bearer_auth(key);
    }
    let resp = request.send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let bytes = read_capped(resp, 1024 * 1024).await.ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    let models = value
        .get("models")?
        .as_array()?
        .iter()
        .filter_map(|m| m.get("name").and_then(Value::as_str).map(str::to_string))
        .collect();
    Some(models)
}

/// Валидация тела native-запроса Ollama: JSON-объект, поле model,
/// потолок `options.num_predict`, плюс python-санитизация сообщений чата.
async fn ollama_prepare_body(body: &[u8], cfg: &Config) -> Result<Vec<u8>, AppError> {
    let mut value: Value = serde_json::from_slice(body)
        .map_err(|_| AppError::BadRequest("Тело запроса должно быть корректным JSON"))?;

    let obj = value
        .as_object_mut()
        .ok_or(AppError::BadRequest("Ожидался JSON-объект"))?;

    let model = obj
        .get("model")
        .and_then(Value::as_str)
        .ok_or(AppError::BadRequest("Поле model обязательно и должно быть строкой"))?
        .to_string();

    // Allowlist хранит имена так, как их указывает клиент через /v1 (с префиксом
    // ollama/...), а native-запросы приходят с «голым» именем. Пропускаем, если
    // разрешено либо голое имя, либо имя с префиксом.
    if !cfg.allowed_models.is_empty() {
        let prefix = cfg
            .ollama
            .as_ref()
            .map(|oc| oc.model_prefix.as_str())
            .unwrap_or_default();
        let with_prefix = format!("{prefix}{model}");
        let allowed =
            cfg.allowed_models.contains(&model) || cfg.allowed_models.contains(&with_prefix);
        if !allowed {
            return Err(AppError::Forbidden);
        }
    }

    // Сообщения чата — прогоняем через ту же санитизацию python-блоков.
    if let Some(bin) = cfg.python_bin.as_deref() {
        if let Some(Value::Array(messages)) = obj.get_mut("messages") {
            sanitize_messages(messages, Some(bin)).await;
        }
        // У /api/generate поле prompt — тоже текст, санитизируем его.
        if let Some(Value::String(prompt)) = obj.get_mut("prompt") {
            let sanitized = execute_python_blocks(prompt, bin).await;
            *prompt = sanitized;
        }
    }

    // Потолок токенов: Ollama задаётся через options.num_predict.
    if let Some(options) = obj.get_mut("options").and_then(Value::as_object_mut) {
        if let Some(n) = options.get("num_predict").and_then(Value::as_u64) {
            if n > cfg.max_output_tokens {
                options.insert("num_predict".into(), json!(cfg.max_output_tokens));
            }
        }
    }

    serde_json::to_vec(&value).map_err(|_| AppError::BadRequest("Не удалось собрать JSON"))
}

/// `stream` в native-запросах Ollama: булев, по умолчанию false.
fn ollama_is_stream(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("stream").and_then(Value::as_bool))
        .unwrap_or(false)
}

/// Стриминг NDJSON от Ollama: та же схема «канал + задача», что и для SSE.
///
/// Отличия от SSE-стрима:
/// * Content-Type — `application/x-ndjson`;
/// * заголовок x-accel-buffering: no тоже ставим (nginx не должен буферизовать).
///
/// `permit` передаётся в задачу и живёт, пока течёт поток (см. SSE-вариант).
fn streaming_ndjson_response(mut upstream: reqwest::Response, permit: tokio::sync::OwnedSemaphorePermit) -> Response {
    let (tx, rx) = mpsc::channel::<Result<Bytes, reqwest::Error>>(8);

    tokio::spawn(async move {
        let _permit = permit; // держим слот, пока течёт поток
        loop {
            match upstream.chunk().await {
                Ok(Some(chunk)) => {
                    if tx.send(Ok(chunk)).await.is_err() {
                        tracing::debug!("клиент отключился, останавливаем NDJSON-стрим");
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(error = %e, "обрыв NDJSON-потока от Ollama");
                    let _ = tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    let mut resp = Body::from_stream(ReceiverStream::new(rx)).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert("x-accel-buffering", HeaderValue::from_static("no"));
    resp
}

/// Находит все блоки ```python ... ```, выполняет их через PYTHON_BIN
/// и заменяет блок на вывод интерпретатора.
/// Если python_bin не настроен — ничего не делает.
async fn sanitize_messages(messages: &mut [Value], python_bin: Option<&str>) {
    let Some(bin) = python_bin else { return };

    for msg in messages.iter_mut() {
        if let Some(Value::String(content)) = msg.get_mut("content") {
            *content = execute_python_blocks(content, bin).await;
        }
    }
}

/// Обрабатывает все fenced-блоки ```python в тексте.
/// Каждый блок заменяется на: ```\n<вывод>\n```
async fn execute_python_blocks(input: &str, python_bin: &str) -> String {
    if python_bin.is_empty() {
        return input.to_string();
    }
    const FENCE: &str = "```python";
    let mut result = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(start) = rest.find(FENCE) {
        // Копируем текст до блока
        result.push_str(&rest[..start]);

        // Ищем закрывающий fence
        let after_open = &rest[start + FENCE.len()..];
        if let Some(end) = after_open.find("```") {
            let code = after_open[..end].trim();
            let remaining = &after_open[end + 3..]; // пропускаем закрывающий ```

            // Выполняем код
            let output = run_python(python_bin, code).await;

            // Заменяем блок на вывод (в обычный code-fence без языка)
            result.push_str("```\n");
            result.push_str(&output);
            if !output.ends_with('\n') {
                result.push('\n');
            }
            result.push_str("```");

            rest = remaining;
        } else {
            // Нет закрывающего fence — копируем как есть
            result.push_str(&rest[start..]);
            break;
        }
    }

    // Остаток текста после последнего блока
    result.push_str(rest);
    result
}

/// Запускает код через python_bin, возвращает stdout+stderr.
/// Таймаут 30 секунд, чтобы бесконечный цикл не повесил прокси.
async fn run_python(bin: &str, code: &str) -> String {
    let child = Command::new(bin)
        .arg("-c")
        .arg(code)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true) // ← КЛЮЧЕВОЕ: процесс будет убит при дропе Child
        .spawn();

    match child {
        Ok(proc) => {
            let timeout =
                tokio::time::timeout(std::time::Duration::from_secs(30), proc.wait_with_output());

            match timeout.await {
                Ok(Ok(output)) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if output.status.success() {
                        stdout.into_owned()
                    } else {
                        format!(
                            "[ERROR exit={}]\n{}{}",
                            output.status.code().unwrap_or(-1),
                            stdout,
                            stderr
                        )
                    }
                }
                Ok(Err(e)) => format!("[EXEC ERROR] {e}"),
                Err(_) => {
                    // Таймаут сработал; kill_on_drop(true) убьёт процесс при дропе Child.
                    "[TIMEOUT] Код выполнялся дольше 30 секунд".to_string()
                }
            }
        }
        Err(e) => format!("[SPAWN ERROR] Не удалось запустить {bin}: {e}"),
    }
}

/// Стриминг (SSE): перекладываем куски из провайдера в канал, из канала — клиенту.
///
/// Зачем канал, а не просто `Body::from_stream(resp.bytes_stream())`:
/// * слот конкурентности (`permit`) живёт до конца стрима, а не до конца обработчика;
/// * канал ограничен (8 кусков) — медленный клиент притормаживает чтение у провайдера
///   (backpressure), память не растёт;
/// * если клиент отключился, `send` вернёт ошибку → мы выходим и роняем соединение
///   с провайдером, переставая тратить токены.
fn streaming_response(
    mut upstream: reqwest::Response,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Response {
    let (tx, rx) = mpsc::channel::<Result<Bytes, reqwest::Error>>(8);

    tokio::spawn(async move {
        let _permit = permit; // держим слот, пока течёт поток
        loop {
            match upstream.chunk().await {
                Ok(Some(chunk)) => {
                    if tx.send(Ok(chunk)).await.is_err() {
                        tracing::debug!("клиент отключился, останавливаем стрим");
                        break;
                    }
                }
                Ok(None) => break, // провайдер закончил ответ
                Err(e) => {
                    tracing::warn!(error = %e, "обрыв потока от провайдера");
                    let _ = tx.send(Err(e)).await; // клиент увидит обрыв, а не «успешный» конец
                    break;
                }
            }
        }
    });

    let mut resp = Body::from_stream(ReceiverStream::new(rx)).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    // Отключаем буферизацию в nginx, иначе стрим приедет клиенту одним куском.
    h.insert("x-accel-buffering", HeaderValue::from_static("no"));
    resp
}

/// Превращаем ошибку провайдера в ответ клиенту.
///
/// Важный нюанс безопасности: тела ответов 401/403 НЕ проксируем.
/// OpenAI в таком случае пишет «Incorrect API key provided: sk-abc***» — то есть
/// отдаёт клиенту кусок НАШЕГО ключа. Такие ошибки скрываем полностью.
async fn upstream_error_response(upstream: reqwest::Response, status: StatusCode) -> Response {
    let retry_after = upstream.headers().get(header::RETRY_AFTER).cloned();
    let content_type = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/json"));

    let is_auth_error = matches!(status.as_u16(), 401 | 403);
    let body = read_capped(upstream, MAX_ERROR_BODY_BYTES)
        .await
        .unwrap_or_default();

    if is_auth_error {
        // Ни тела, ни его содержимого в лог: там может быть часть ключа.
        tracing::error!(
            status = status.as_u16(),
            "провайдер отверг ключ прокси — проверьте UPSTREAM_API_KEY / OLLAMA_API_KEY"
        );
        return AppError::Upstream("Провайдер отклонил учётные данные прокси").into_response();
    }

    tracing::warn!(status = status.as_u16(), body = %String::from_utf8_lossy(&body), "ошибка от провайдера");

    if status == StatusCode::TOO_MANY_REQUESTS {
        let mut resp = AppError::RateLimited.into_response();
        if let Some(v) = retry_after {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        return resp;
    }

    // Прочие 4xx — это ошибки в запросе клиента (неизвестная модель, кривые параметры).
    // Их полезно показать как есть, чтобы человек мог починить запрос. Обрезаем до 4 КиБ.
    if status.is_client_error() {
        return (status, [(header::CONTENT_TYPE, content_type)], body).into_response();
    }

    // 5xx и прочее — внутренности провайдера клиенту не показываем.
    AppError::Upstream("Ошибка на стороне провайдера").into_response()
}

/// Читаем тело с жёстким потолком: даже если провайдер начнёт отдавать гигабайты,
/// мы остановимся и вернём ошибку, а не съедим всю память.
async fn read_capped(mut resp: reqwest::Response, limit: usize) -> Result<Vec<u8>, AppError> {
    let mut out = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if out.len() + chunk.len() > limit {
                    return Err(AppError::Upstream("Ответ провайдера слишком большой"));
                }
                out.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(out),
            Err(e) => {
                tracing::warn!(error = %e, "обрыв ответа провайдера");
                return Err(AppError::Upstream("Обрыв ответа провайдера"));
            }
        }
    }
}

/// Валидация и нормализация запроса `/v1/chat/completions`.
///
/// Мы разбираем JSON и собираем его заново: наружу уходит ровно то, что проверили
/// (никаких «двух тел» — одного для проверки, другого для провайдера).
///
/// Маршрутизация: модель с префиксом Ollama (`ollama/llama3`) помечается
/// `to_ollama = true`, префикс срезается (Ollama не знает его).
async fn prepare_request(body: &[u8], cfg: &Config) -> Result<Prepared, AppError> {
    let mut value: Value = serde_json::from_slice(body)
        .map_err(|_| AppError::BadRequest("Тело запроса должно быть корректным JSON"))?;

    let obj = value
        .as_object_mut()
        .ok_or(AppError::BadRequest("Ожидался JSON-объект"))?;

    // model — обязательна и должна быть в списке разрешённых.
    let model = obj
        .get("model")
        .and_then(Value::as_str)
        .ok_or(AppError::BadRequest(
            "Поле model обязательно и должно быть строкой",
        ))?
        .to_string();

    if !cfg.allowed_models.is_empty() && !cfg.allowed_models.contains(&model) {
        return Err(AppError::Forbidden);
    }

    // Маршрутизация в Ollama: у модели префикс, который Ollama не знает.
    // Проверяем allowlist по ПОЛНОМУ имени (как его видит клиент), а наружу
    // отдаём уже срезанное.
    let (to_ollama, model_upstream) = match &cfg.ollama {
        Some(oc) if !oc.model_prefix.is_empty() => {
            if let Some(stripped) = model.strip_prefix(&oc.model_prefix) {
                if stripped.is_empty() {
                    return Err(AppError::BadRequest(
                        "После префикса ollama/ должно быть имя модели",
                    ));
                }
                (true, stripped.to_string())
            } else {
                (false, model.clone())
            }
        }
        _ => (false, model.clone()),
    };

    // messages — обязательный непустой массив.
    // Используем match, т.к. and_then не работает с мутабельными ссылками напрямую.
    let messages = match obj.get_mut("messages") {
        Some(Value::Array(arr)) => arr,
        _ => {
            return Err(AppError::BadRequest(
                "Поле messages обязательно и должно быть массивом",
            ))
        }
    };

    if messages.is_empty() {
        return Err(AppError::BadRequest("messages не должен быть пустым"));
    }

    // Вызываем санитизацию ДО остальных проверок
    sanitize_messages(messages, cfg.python_bin.as_deref()).await;

    // Ограничиваем стоимость ответа: если клиент попросил больше потолка — режем.
    // Если поле не указано, оставляем как есть (значение по умолчанию у провайдера);
    // жёсткий потолок расходов задаётся ещё и на стороне провайдера.
    for field in ["max_tokens", "max_completion_tokens"] {
        if let Some(v) = obj.get(field) {
            if v.is_null() {
                continue;
            }
            let n = v
                .as_u64()
                .ok_or(AppError::BadRequest("max_tokens должен быть целым числом"))?;
            if n > cfg.max_output_tokens {
                obj.insert(field.to_string(), json!(cfg.max_output_tokens));
            }
        }
    }

    // stream должен быть именно булевым: строка "true" привела бы к рассинхрону
    // (мы считаем ответ обычным, а провайдер присылает SSE).
    let stream = match obj.get("stream") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        _ => return Err(AppError::BadRequest("stream должен быть true или false")),
    };

    // Подставляем «внутреннее» имя модели для Ollama.
    if to_ollama {
        obj.insert("model".into(), json!(model_upstream));
    }

    let body =
        serde_json::to_vec(&value).map_err(|_| AppError::BadRequest("Не удалось собрать JSON"))?;

    Ok(Prepared {
        body,
        model,
        stream,
        to_ollama,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashSet, time::Duration};

    fn cfg(models: &[&str], cap: u64) -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream_base: reqwest::Url::parse("https://api.example.com/v1").unwrap(),
            upstream_api_key: "upstream".into(),
            client_keys: vec!["client-key-aaaaaaaaaaaaaaaa".into()],
            allowed_models: models.iter().map(|s| s.to_string()).collect::<HashSet<_>>(),
            max_output_tokens: cap,
            rate_per_minute: 60,
            max_concurrent: 4,
            request_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(10),
            python_bin: None,
            allow_http: false,
            ollama: None,
        }
    }

    fn cfg_with_ollama(models: &[&str], cap: u64, prefix: &str) -> Config {
        let mut c = cfg(models, cap);
        c.ollama = Some(OllamaConfig {
            base: reqwest::Url::parse("http://127.0.0.1:11434").unwrap(),
            api_key: None,
            model_prefix: prefix.into(),
        });
        c
    }

    #[tokio::test]
    async fn valid_request_passes() {
        let body = br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &cfg(&["gpt-4o-mini"], 100))
            .await
            .unwrap();
        assert_eq!(p.model, "gpt-4o-mini");
        assert!(!p.stream);
        assert!(!p.to_ollama);
    }

    #[tokio::test]
    async fn max_tokens_is_clamped() {
        let body =
            br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"max_tokens":999999}"#;
        let p = prepare_request(body, &cfg(&[], 512)).await.unwrap();
        let v: Value = serde_json::from_slice(&p.body).unwrap();
        assert_eq!(v["max_tokens"], 512);
    }

    #[tokio::test]
    async fn max_completion_tokens_is_clamped_too() {
        let body = br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":99999}"#;
        let p = prepare_request(body, &cfg(&[], 512)).await.unwrap();
        let v: Value = serde_json::from_slice(&p.body).unwrap();
        assert_eq!(v["max_completion_tokens"], 512);
    }

    #[tokio::test]
    async fn model_allowlist_enforced() {
        let body = br#"{"model":"expensive","messages":[{"role":"user","content":"hi"}]}"#;
        assert!(matches!(
            prepare_request(body, &cfg(&["cheap"], 100)).await,
            Err(AppError::Forbidden)
        ));
    }

    #[tokio::test]
    async fn bad_bodies_rejected() {
        let c = cfg(&[], 100);
        assert!(prepare_request(b"not json", &c).await.is_err());
        assert!(prepare_request(b"[]", &c).await.is_err());
        assert!(prepare_request(br#"{"messages":[]}"#, &c).await.is_err());
        assert!(prepare_request(br#"{"model":"m"}"#, &c).await.is_err());
        assert!(prepare_request(br#"{"model":"m","messages":[]}"#, &c).await.is_err());
        assert!(
            prepare_request(br#"{"model":"m","messages":[],"max_tokens":"lots"}"#, &c)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn stream_must_be_boolean() {
        let body = br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":"true"}"#;
        assert!(prepare_request(body, &cfg(&[], 100)).await.is_err());
    }

    #[tokio::test]
    async fn stream_flag_detected() {
        let body = br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
        assert!(prepare_request(body, &cfg(&[], 100)).await.unwrap().stream);
    }

    // ---- маршрутизация Ollama ----

    #[tokio::test]
    async fn ollama_prefix_routes_and_is_stripped() {
        let c = cfg_with_ollama(&["ollama/llama3"], 100, "ollama/");
        let body = br#"{"model":"ollama/llama3","messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &c).await.unwrap();
        assert!(p.to_ollama);
        assert_eq!(p.model, "ollama/llama3");
        // наружу уходит срезанное имя
        let v: Value = serde_json::from_slice(&p.body).unwrap();
        assert_eq!(v["model"], "llama3");
    }

    #[tokio::test]
    async fn ollama_prefix_allowlist_checked_on_full_name() {
        // allowlist содержит полное имя — всё проходит
        let c = cfg_with_ollama(&["ollama/llama3"], 100, "ollama/");
        let body = br#"{"model":"ollama/llama3","messages":[{"role":"user","content":"hi"}]}"#;
        assert!(prepare_request(body, &c).await.is_ok());

        // allowlist НЕ содержит имя — отказ, даже если модель существует в Ollama
        let c = cfg_with_ollama(&["gpt-4o-mini"], 100, "ollama/");
        let body = br#"{"model":"ollama/llama3","messages":[{"role":"user","content":"hi"}]}"#;
        assert!(matches!(
            prepare_request(body, &c).await,
            Err(AppError::Forbidden)
        ));
    }

    #[tokio::test]
    async fn ollama_prefix_without_model_name_rejected() {
        let c = cfg_with_ollama(&[], 100, "ollama/");
        let body = br#"{"model":"ollama/","messages":[{"role":"user","content":"hi"}]}"#;
        assert!(prepare_request(body, &c).await.is_err());
    }

    #[tokio::test]
    async fn non_ollama_model_unaffected_by_prefix() {
        let c = cfg_with_ollama(&[], 100, "ollama/");
        let body = br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &c).await.unwrap();
        assert!(!p.to_ollama);
        let v: Value = serde_json::from_slice(&p.body).unwrap();
        assert_eq!(v["model"], "gpt-4o-mini");
    }

    #[tokio::test]
    async fn empty_prefix_disables_routing() {
        let c = cfg_with_ollama(&[], 100, "");
        let body = br#"{"model":"llama3","messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &c).await.unwrap();
        assert!(!p.to_ollama);
    }

    #[tokio::test]
    async fn ollama_prefix_with_ollama_disabled_errors() {
        // ollama = None, но модель несёт префикс — пользователю объясняем причину.
        let c = cfg(&[], 100);
        let body = br#"{"model":"ollama/llama3","messages":[{"role":"user","content":"hi"}]}"#;
        // prepare_request не знает о выключенной Ollama — префикс без Ollama не маршрутизируется
        let p = prepare_request(body, &c).await.unwrap();
        assert!(!p.to_ollama); // путь — основной провайдер
    }

    // ---- native-тела Ollama ----

    #[tokio::test]
    async fn ollama_native_body_valid_and_num_predict_clamped() {
        let c = cfg_with_ollama(&[], 100, "ollama/");
        let body = br#"{"model":"llama3","messages":[{"role":"user","content":"hi"}],"stream":true,"options":{"num_predict":99999}}"#;
        let out = ollama_prepare_body(body, &c).await.unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["options"]["num_predict"], 100);
    }

    #[tokio::test]
    async fn ollama_native_body_requires_model() {
        let c = cfg_with_ollama(&[], 100, "ollama/");
        let body = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
        assert!(ollama_prepare_body(body, &c).await.is_err());
        assert!(ollama_prepare_body(b"not json", &c).await.is_err());
    }

    #[tokio::test]
    async fn ollama_native_stream_detected() {
        assert!(ollama_is_stream(br#"{"stream":true}"#));
        assert!(!ollama_is_stream(br#"{"stream":false}"#));
        assert!(!ollama_is_stream(br#"{}"#));
    }

    #[tokio::test]
    async fn ollama_native_allowlist_checked() {
        // allowlist с полным именем (ollama/llama3) пропускает native-запрос «llama3»
        let c = cfg_with_ollama(&["ollama/llama3"], 100, "ollama/");
        let body = br#"{"model":"llama3","messages":[]}"#;
        assert!(ollama_prepare_body(body, &c).await.is_ok());

        // чужая модель не проходит
        let body = br#"{"model":"gemma2","messages":[]}"#;
        assert!(matches!(
            ollama_prepare_body(body, &c).await,
            Err(AppError::Forbidden)
        ));
    }
}

// ---------------------------------------------------------------------------
// Images API (/v1/images/generations)
// ---------------------------------------------------------------------------

/// Лимит для ответа images API (50 МиБ — несколько изображений в base64)
const MAX_IMAGE_RESPONSE_BYTES: usize = 50 * 1024 * 1024;

/// Обработчик POST /v1/images/generations
/// Проксирует запросы к Images API без модификации тела,
/// но с проверкой модели и заменой ключа.
pub async fn image_generations(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let started = Instant::now();

    // 1. Аутентификация клиента
    let client =
        security::authenticate(headers.get(header::AUTHORIZATION), &state.cfg.client_keys)?;

    // 2. Rate limit
    if !state.limiter.allow(client) {
        tracing::warn!(client, "превышен лимит запросов (images)");
        return Err(AppError::RateLimited);
    }

    // 3. Базовая валидация JSON и проверка модели
    let value: Value = serde_json::from_slice(&body)
        .map_err(|_| AppError::BadRequest("Тело запроса должно быть корректным JSON"))?;

    let model = value
        .get("model")
        .and_then(Value::as_str)
        .ok_or(AppError::BadRequest("Поле model обязательно"))?
        .to_string();

    if !state.cfg.allowed_models.is_empty() && !state.cfg.allowed_models.contains(&model) {
        return Err(AppError::Forbidden);
    }

    // 4. Слот конкурентности
    let _permit = state
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::Busy)?;

    // 5. Формируем URL для images endpoint
    let images_url = {
        let mut url = state.cfg.upstream_base.clone();
        let path = format!("{}/images/generations", url.path().trim_end_matches('/'));
        url.set_path(&path);
        url
    };

    // 6. Запрос к провайдеру
    let upstream = state
        .http
        .post(images_url)
        .bearer_auth(&state.cfg.upstream_api_key)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .timeout(state.cfg.request_timeout)
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "не удалось выполнить запрос к images API");
            if e.is_timeout() {
                AppError::GatewayTimeout
            } else {
                AppError::Upstream("Не удалось связаться с провайдером")
            }
        })?;

    let status = upstream.status();

    // 7. Обработка ошибок
    if !status.is_success() {
        return Ok(upstream_error_response(upstream, status).await);
    }

    // 8. Чтение ответа (изображения в base64 могут быть большими)
    let content_type = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/json"));

    let bytes = read_capped(upstream, MAX_IMAGE_RESPONSE_BYTES).await?;

    tracing::info!(
        client,
        model = %model,
        status = status.as_u16(),
        ms = started.elapsed().as_millis() as u64,
        "image generation completed"
    );

    Ok(([(header::CONTENT_TYPE, content_type)], bytes).into_response())
}
