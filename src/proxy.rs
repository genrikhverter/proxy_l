//! Главная логика прокси: проверить запрос → отправить провайдеру → вернуть ответ.
//!
//! Порядок проверок важен: сначала дешёвые (ключ, лимит, JSON), и только потом
//! дорогой сетевой запрос. Так мусорный трафик не доходит до платного API.

use std::time::Instant;

use crate::{
    config::{Config, MAX_ERROR_BODY_BYTES, MAX_RESPONSE_BYTES},
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
}

/// Обработчик POST /v1/chat/completions.
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

    // 4. Слот конкурентности: не больше N одновременных обращений к провайдеру.
    //    try_acquire — не ждём в очереди, а сразу отвечаем 503 (честный backpressure).
    let permit = state
        .slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::Busy)?;

    // 5. Запрос к провайдеру. Заголовки собираем с нуля — это «белый список»:
    //    ни Authorization клиента, ни Cookie, ни Host не утекут наружу.
    let mut request = state
        .http
        .post(state.cfg.chat_completions_url())
        .bearer_auth(&state.cfg.upstream_api_key) // <-- настоящий ключ подставляется здесь
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

    if !prepared.stream {
        // Полный таймаут ставим ТОЛЬКО нестриминговым запросам:
        // у стрима ответ может идти минутами, и общий таймаут оборвал бы его на середине.
        // Для стрима работают connect_timeout и read_timeout (простой между кусками).
        request = request.timeout(state.cfg.request_timeout);
    }

    let upstream = request.send().await.map_err(|e| {
        // В лог идёт текст ошибки reqwest (URL, TLS, таймаут) — заголовков и ключей там нет.
        tracing::warn!(error = %e, "не удалось выполнить запрос к провайдеру");
        if e.is_timeout() {
            AppError::GatewayTimeout
        } else {
            AppError::Upstream("Не удалось связаться с провайдером")
        }
    })?;

    let status = upstream.status();

    // 6. Провайдер вернул ошибку.
    if !status.is_success() {
        return Ok(upstream_error_response(upstream, status).await);
    }

    // 7. Успех: стрим или обычный ответ.
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
        stream = prepared.stream,
        status = status.as_u16(),
        ms = started.elapsed().as_millis() as u64,
        "запрос обработан"
    );
    Ok(response)
}
// proxy.rs

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

            // Заменяем блок на вывод (в обычном code-fence без языка)
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
                    // Таймаут сработал.
                    // proc уже был moved в wait_with_output, но kill_on_drop(true)
                    // гарантирует, что процесс будет убит когда Child упадёт.
                    // Однако wait_with_output может продолжать читать пайпы.
                    // Мы просто сообщаем о таймауте — процесс умрёт при дропе.
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
            "провайдер отверг ключ прокси — проверьте UPSTREAM_API_KEY"
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

/// Валидация и нормализация запроса.
///
/// Мы разбираем JSON и собираем его заново: наружу уходит ровно то, что проверили
/// (никаких «двух тел» — одного для проверки, другого для провайдера).
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
    let body =
        serde_json::to_vec(&value).map_err(|_| AppError::BadRequest("Не удалось собрать JSON"))?;

    Ok(Prepared {
        body,
        model,
        stream,
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
            python_bin: None, // Обязательно для новой структуры Config
        }
    }

    #[tokio::test]
    async fn valid_request_passes() {
        let body = br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &cfg(&["gpt-4o-mini"], 100))
            .await
            .unwrap();
        assert_eq!(p.model, "gpt-4o-mini");
        assert!(!p.stream);
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
        assert!(prepare_request(br#"{"model":"m","messages":[]}"#, &c)
            .await
            .is_err());
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
}

// proxy.rs

/// Обработчик POST /v1/images/generations
/// Проксирует запросы к OpenRouter Images API без модификации тела,
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

/// Лимит для ответа images API (50 МиБ — несколько изображений в base64)
const MAX_IMAGE_RESPONSE_BYTES: usize = 50 * 1024 * 1024;
