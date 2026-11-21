//! Главная логика прокси: проверить запрос → отправить провайдеру → вернуть ответ.
//!
//! Порядок проверок важен: сначала дешёвые (ключ, лимит, JSON), и только потом
//! дорогой сетевой запрос. Так мусорный трафик не доходит до платного API.
//!
//! Доступ унифицирован: все провайдеры из `cfg.providers` (по приоритету)
//! получают ОДИНАКОВЫЙ OpenAI-совместимый запрос. Если провайдер не отвечает
//! (ошибка сети, таймаут) или вернул отказ (401/403/404/408/429/5xx),
//! тот же запрос уходит следующему по приоритету. Прочие 4xx — ошибка в самом
//! запросе клиента, повторять её на других провайдерах бессмысленно.
//!
//! Ollama — обычный провайдер в этом списке (kind = Ollama); её native-эндпоинты
//! `/api/*` проксируются на первого провайдера типа Ollama без failover:
//! там протокол свой (NDJSON), заменить его другим провайдером нельзя.

use std::time::Instant;

use crate::{
    config::{Config, ProviderConfig, ProviderKind, MAX_ERROR_BODY_BYTES, MAX_RESPONSE_BYTES},
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
    Busy,                     // 503 — все слоты к провайдерам заняты
    Upstream(&'static str),   // 502 — проблема на стороне провайдера
    /// 502 — ни один провайдер из списка не ответил (с динамической причиной).
    UpstreamAll(String),
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
            AppError::UpstreamAll(m) => {
                // Динамическое сообщение: возвращаем ответ сразу, не выходя из match.
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error": {"message": m, "type": "upstream_error"}})),
                )
                    .into_response();
            }
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
    /// Разобранный JSON (санитизирован, потолки токенов срезаны). Тело для
    /// конкретного провайдера собирается в dispatch — с ЕГО моделью.
    pub value: Value,
    /// Имя модели так, как его указал клиент (для логов и allowlist).
    /// `None` — клиент не указал `model` (нет, null, пустая строка, "all").
    pub model: Option<String>,
    /// Модель, которую кладём в поле `model` исходящего запроса:
    /// клиентская (без префикса провайдера). `None` — подставляется
    /// default-модель того провайдера, который реально обслужит запрос.
    pub send_model: Option<String>,
    pub stream: bool,
    /// Индекс провайдера, выбранного ЯВНО по префиксу модели (`ollama/llama3`).
    /// `None` — идём по приоритету через весь список с failover.
    pub explicit: Option<usize>,
}

impl Prepared {
    /// Тело запроса для конкретного провайдера: поле `model` = клиентская
    /// модель или default-модель этого провайдера (когда клиент её не указал).
    /// `None` — у провайдера нет default-модели, а клиент не назвал модель:
    /// такой провайдер из запроса без `model` пропускается.
    fn body_for(&self, p: &ProviderConfig) -> Option<Vec<u8>> {
        let mut value = self.value.clone();
        let obj = value.as_object_mut()?;
        let model = match &self.send_model {
            Some(m) => m.clone(),
            None => p.default_model.clone()?,
        };
        obj.insert("model".into(), json!(model));
        serde_json::to_vec(&value).ok()
    }
}

/// Какой OpenAI-совместимый эндпоинт вызываем у провайдера.
#[derive(Clone, Copy)]
enum Endpoint {
    ChatCompletions,
    Images,
}

impl Endpoint {
    fn url(self, p: &ProviderConfig) -> reqwest::Url {
        match self {
            Endpoint::ChatCompletions => p.chat_completions_url(),
            Endpoint::Images => p.images_url(),
        }
    }
}

/// Результат dispatch: успех у одного из провайдеров или готовый ответ клиенту.
enum Dispatched {
    /// 2xx от провайдера. `permit` держит слот — для стрима он живёт до конца потока.
    Upstream {
        response: reqwest::Response,
        permit: tokio::sync::OwnedSemaphorePermit,
        provider: usize,
    },
    /// Не-фейловерная 4xx-ошибка провайдера: отд клиенту как есть
    /// (тело уже прочитано и приведено к безопасному виду).
    Passthrough(Response),
}

/// Статусы, при которых запрос стоит повторить у следующего провайдера:
/// * 401/403 — провайдер отверг НАШ ключ (он у этого провайдера не настроен/протух);
/// * 404 — у провайдера нет такой модели или эндпоинта;
/// * 408 — таймаут на стороне провайдера;
/// * 429 — квота/лимит провайдера исчерпаны;
/// * 5xx — авария на стороне провайдера.
/// Прочие 4xx (400, 413, 422...) означают проблему в самом запросе —
/// на другом провайдере будет та же ошибка, не тратим попытки.
fn is_failover_status(status: StatusCode) -> bool {
    matches!(status.as_u16(), 401 | 403 | 404 | 408 | 429) || status.is_server_error()
}

/// Единая отправка запроса по списку провайдеров с failover по приоритету.
///
/// Для каждого кандидата по порядку: берём слот конкурентности, собираем тело
/// С МОДЕЛЬЮ ЭТОГО провайдера (клиентскую или его default — у провайдеров
/// разные каталоги моделей), отправляем; при сетевой ошибке, таймауте или
/// фейловерном статусе — переходим к следующему. Провайдер без default-модели
/// из запроса без `model` пропускается. Первый успешный 2xx возвращается
/// вместе со слотом (для стрима слот должен жить до конца потока).
async fn dispatch_with_failover(
    state: &AppState,
    candidates: &[usize],
    endpoint: Endpoint,
    prepared: &Prepared,
    accept: &'static str,
    // Полный таймаут ставим ТОЛЬКО нестриминговым запросам: у стрима ответ
    // может идти минутами, и общий таймаут оборвал бы его на середине.
    // Для стрима работают connect_timeout и read_timeout (простой между кусками).
    with_total_timeout: bool,
) -> Result<Dispatched, AppError> {
    let mut last_status: Option<u16> = None;
    let mut busy: usize = 0;
    let mut no_default: usize = 0;

    for &idx in candidates {
        let p = &state.cfg.providers[idx];

        // Тело для ЭТОГО провайдера: model = клиентская или его default.
        let Some(body) = prepared.body_for(p) else {
            tracing::warn!(
                provider = %p.name,
                "в запросе нет model, а у провайдера нет модели по умолчанию (model= в UPSTREAMS) — пропускаем"
            );
            no_default += 1;
            continue;
        };

        // Слот конкурентности: не больше N одновременных обращений к этому
        // провайдеру. try_acquire — не ждём в очереди: если провайдер занят,
        // честнее сразу попробовать следующего по приоритету.
        let permit = match state.slots[idx].clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                busy += 1;
                tracing::warn!(provider = %p.name, "слоты провайдера заняты, пробуем следующего по приоритету");
                continue;
            }
        };

        // Заголовки собираем с нуля — это «белый список»: ни Authorization
        // клиента, ни Cookie, ни Host не утекут наружу. Ключ подставляется
        // только здесь; провайдер без ключа (локальная Ollama) остаётся
        // без Authorization вовсе.
        let mut request = state
            .http
            .post(endpoint.url(p))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, accept)
            .body(body);

        if let Some(key) = &p.api_key {
            request = request.bearer_auth(key);
        }
        if with_total_timeout {
            request = request.timeout(state.cfg.request_timeout);
        }

        match request.send().await {
            Err(e) => {
                // В лог идёт текст ошибки reqwest (URL, TLS, таймаут) — заголовков и ключей там нет.
                tracing::warn!(
                    provider = %p.name,
                    error = %e,
                    "провайдер не ответил, переходим к следующему по приоритету"
                );
                drop(permit);
                continue;
            }
            Ok(upstream) => {
                let status = upstream.status();
                if status.is_success() {
                    return Ok(Dispatched::Upstream {
                        response: upstream,
                        permit,
                        provider: idx,
                    });
                }

                if is_failover_status(status) {
                    // Тело ошибки читаем для лога; 401/403 могут содержать
                    // кусок нашего ключа — такое содержимое в лог не пишем.
                    let error_body = read_capped(upstream, MAX_ERROR_BODY_BYTES)
                        .await
                        .unwrap_or_default();
                    if matches!(status.as_u16(), 401 | 403) {
                        tracing::error!(
                            provider = %p.name,
                            status = status.as_u16(),
                            "провайдер отверг ключ прокси — проверьте api_key этого провайдера в UPSTREAMS (тело ошибки скрыто)"
                        );
                    } else {
                        tracing::warn!(
                            provider = %p.name,
                            status = status.as_u16(),
                            body = %String::from_utf8_lossy(&error_body),
                            "провайдер вернул отказ, переходим к следующему по приоритету"
                        );
                    }
                    last_status = Some(status.as_u16());
                    drop(permit);
                    continue;
                }

                // Прочие 4xx — ошибка в запросе клиента (неизвестные параметры,
                // кривой JSON и т.п.). Повтор на другом провайдере даст тот же
                // результат — отдаём ответ как есть.
                return Ok(Dispatched::Passthrough(
                    upstream_error_response(upstream, status).await,
                ));
            }
        }
    }

    if !candidates.is_empty() && busy == candidates.len() {
        // Все слоты всех кандидатов заняты — это наша перегрузка, не вина провайдеров.
        return Err(AppError::Busy);
    }

    if no_default == candidates.len() {
        // Ни у одного провайдера нет default-модели, а клиент не назвал модель.
        return Err(AppError::BadRequest(
            "Поле model обязательно: ни у одного провайдера нет модели по умолчанию \
             (задайте model=<имя> в UPSTREAMS)",
        ));
    }

    Err(AppError::UpstreamAll(format!(
        "Ни один из {} провайдеров не обработал запрос{}",
        candidates.len() - no_default,
        last_status
            .map(|s| format!(" (последний ответ провайдера: HTTP {s})"))
            .unwrap_or_default()
    )))
}

/// Обработчик POST /v1/chat/completions.
///
/// Модель с префиксом `имя/` уходит ЗАДАННОМУ провайдеру, остальные —
/// первому живому провайдеру по приоритету (с failover по списку).
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

    // 4. Кандидаты по приоритету: явный префикс модели → один провайдер,
    //    иначе — весь список по порядку.
    let candidates: Vec<usize> = match prepared.explicit {
        Some(idx) => vec![idx],
        None => (0..state.cfg.providers.len()).collect(),
    };
    if candidates.is_empty() {
        return Err(AppError::NotFound("Не настроен ни один провайдер"));
    }

    // 5-6. Запрос к провайдерам с failover. Тело собирается в dispatch
    //    отдельно для каждого провайдера (его модель из `model=` в UPSTREAMS).
    let accept = if prepared.stream { "text/event-stream" } else { "application/json" };
    let dispatched = dispatch_with_failover(
        &state,
        &candidates,
        Endpoint::ChatCompletions,
        &prepared,
        accept,
        !prepared.stream,
    )
    .await?;

    // 7. Успех: стрим или обычный ответ.
    let response = match dispatched {
        Dispatched::Passthrough(resp) => return Ok(resp),
        Dispatched::Upstream { response: upstream, permit, provider } => {
            let content_type = upstream
                .headers()
                .get(header::CONTENT_TYPE)
                .cloned()
                .unwrap_or_else(|| HeaderValue::from_static("application/json"));

            let resp = if prepared.stream {
                streaming_response(upstream, permit)
            } else {
                let bytes = read_capped(upstream, MAX_RESPONSE_BYTES).await?;
                ([(header::CONTENT_TYPE, content_type)], bytes).into_response()
            };

            // Модель, реально ушедшая провайдеру: клиентская или его default.
            let served_model = prepared
                .send_model
                .clone()
                .or_else(|| state.cfg.providers[provider].default_model.clone())
                .unwrap_or_else(|| "<нет>".into());

            tracing::info!(
                client,
                model = %served_model,
                requested = %prepared.model.as_deref().unwrap_or("<не указана>"),
                provider = %state.cfg.providers[provider].name,
                stream = prepared.stream,
                ms = started.elapsed().as_millis() as u64,
                "запрос обработан"
            );
            resp
        }
    };

    Ok(response)
}

// ---------------------------------------------------------------------------
// Native Ollama API (/api/*)
// ---------------------------------------------------------------------------

/// Общая проверка входа native-эндпоинтов Ollama: аутентификация + лимит.
/// Возвращает (номер клиента, индекс ollama-провайдера, слот конкурентности).
async fn ollama_gate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(usize, usize, tokio::sync::OwnedSemaphorePermit), AppError> {
    let idx = state.cfg.ollama_index().ok_or(AppError::NotFound(
        "Ollama не настроена: нет провайдера ollama в UPSTREAMS",
    ))?;

    let client =
        security::authenticate(headers.get(header::AUTHORIZATION), &state.cfg.client_keys)?;
    if !state.limiter.allow(client) {
        tracing::warn!(client, "превышен лимит запросов (ollama)");
        return Err(AppError::RateLimited);
    }

    let permit = state.slots[idx]
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::Busy)?;

    Ok((client, idx, permit))
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
    let (client, idx, permit) = ollama_gate(&state, &headers).await?;
    let oc = &state.cfg.providers[idx];

    // Валидируем и нормализуем тело: model обязательна, num_predict режем.
    let body = ollama_prepare_body(&body, &state.cfg, oc).await?;

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
        tracing::warn!(error = %e, provider = %oc.name, path, "не удалось выполнить запрос к Ollama");
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
        provider = %oc.name,
        path,
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
    let idx = state.cfg.ollama_index().ok_or(AppError::NotFound("Ollama не настроена"))?;
    let oc = &state.cfg.providers[idx];

    let mut request = state
        .http
        .get(oc.api_url(path))
        .header(header::ACCEPT, "application/json")
        .timeout(state.cfg.request_timeout);
    if let Some(key) = oc.api_key.clone() {
        request = request.bearer_auth(key);
    }

    let upstream = request.send().await.map_err(|e| {
        tracing::warn!(error = %e, provider = %oc.name, path, "не удалось выполнить GET к Ollama");
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

/// Список моделей провайдера для /v1/models. `None` — провайдер недоступен
/// (возвращаем просто без его моделей, не ломаем эндпоинт).
/// У Ollama читаем native `/api/tags` (`models[].name`), у остальных —
/// OpenAI-совместимый `base/models` (`data[].id`).
pub async fn provider_model_list(state: &AppState, idx: usize) -> Option<Vec<String>> {
    let p = &state.cfg.providers[idx];
    let mut request = state
        .http
        .get(p.models_url())
        .timeout(std::time::Duration::from_secs(5));
    if let Some(key) = &p.api_key {
        request = request.bearer_auth(key);
    }
    let resp = request.send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let bytes = read_capped(resp, 1024 * 1024).await.ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    let field = match p.kind {
        ProviderKind::Ollama => "models",
        ProviderKind::OpenAi => "data",
    };
    let name_field = match p.kind {
        ProviderKind::Ollama => "name",
        ProviderKind::OpenAi => "id",
    };
    Some(
        value
            .get(field)?
            .as_array()?
            .iter()
            .filter_map(|m| m.get(name_field).and_then(Value::as_str).map(str::to_string))
            .collect(),
    )
}

/// Валидация тела native-запроса Ollama: JSON-объект, model (или default-модель
/// провайдера), потолок `options.num_predict`, плюс python-санитизация сообщений чата.
async fn ollama_prepare_body(
    body: &[u8],
    cfg: &Config,
    oc: &ProviderConfig,
) -> Result<Vec<u8>, AppError> {
    let mut value: Value = serde_json::from_slice(body)
        .map_err(|_| AppError::BadRequest("Тело запроса должно быть корректным JSON"))?;

    let obj = value
        .as_object_mut()
        .ok_or(AppError::BadRequest("Ожидался JSON-объект"))?;

    // model — необязательна: без неё (или "all") берётся default-модель
    // ollama-провайдера.
    let client_model: Option<String> = client_model_from(obj.get("model"))?;
    let model = match client_model {
        Some(m) => m,
        None => oc.default_model.clone().ok_or(AppError::BadRequest(
            "Поле model обязательно: у ollama-провайдера нет модели по умолчанию \
             (задайте model=<имя> в UPSTREAMS или OLLAMA_MODEL)",
        ))?,
    };
    // Нормализуем тело: модель всегда присутствует (подставленная или клиентская).
    obj.insert("model".into(), json!(model.clone()));

    // Allowlist хранит имена так, как их указывает клиент через /v1 (с префиксом
    // ollama/...), а native-запросы приходят с «голым» именем. Пропускаем, если
    // разрешено либо голое имя, либо имя с префиксом.
    if !cfg.allowed_models.is_empty() {
        let with_prefix = format!("{}{model}", oc.model_prefix);
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
/// Вызывается для НЕ-фейловерных статусов (прочие 4xx): такие ошибки значат
/// «что-то не так с самим запросом», и на другом провайдере ответ был бы тем же.
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
            "провайдер отверг ключ прокси — проверьте api_key провайдера в UPSTREAMS"
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

/// Модель, указанная клиентом в поле `model` запроса.
///
/// `None` — модель НЕ указана: поле отсутствует, `null`, пустая строка или
/// строка `all` (без учёта регистра). В этом случае запрос идёт по приоритету,
/// и каждому провайдеру подставляется ЕГО default-модель (`model=` в UPSTREAMS).
/// Провайдеры без default-модели из такого запроса пропускаются.
fn client_model_from(field: Option<&Value>) -> Result<Option<String>, AppError> {
    match field {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") {
                Ok(None)
            } else {
                Ok(Some(s.clone()))
            }
        }
        Some(_) => Err(AppError::BadRequest(
            "Поле model должно быть строкой (или отсутствовать — тогда берётся \
             модель по умолчанию провайдера)",
        )),
    }
}

/// Валидация и нормализация запроса `/v1/chat/completions`.
///
/// Мы разбираем JSON и собираем его заново: наружу уходит ровно то, что проверили
/// (никаких «двух тел» — одного для проверки, другого для провайдера).
///
/// Маршрутизация: модель с префиксом провайдера (`ollama/llama3`) помечается
/// `explicit = Some(индекс)`, префикс срезается (провайдер его не знает).
/// Модель без префикса идёт по приоритету всего списка.
///
/// Поле `model` НЕобязательно: если клиент его не указал (нет, null, пустая
/// строка или `all` — без учёта регистра), запрос пойдёт по приоритету, и
/// каждому провайдеру будет подставлена ЕГО default-модель (`model=` в
/// UPSTREAMS). Провайдеры без default-модели из такого запроса пропускаются.
async fn prepare_request(body: &[u8], cfg: &Config) -> Result<Prepared, AppError> {
    let mut value: Value = serde_json::from_slice(body)
        .map_err(|_| AppError::BadRequest("Тело запроса должно быть корректным JSON"))?;

    let obj = value
        .as_object_mut()
        .ok_or(AppError::BadRequest("Ожидался JSON-объект"))?;

    // model — необязательна; отсутствует/null/пустая/"all" → default-модель провайдера.
    let client_model: Option<String> = client_model_from(obj.get("model"))?;

    if let Some(model) = &client_model {
        if !cfg.allowed_models.is_empty() && !cfg.allowed_models.contains(model) {
            return Err(AppError::Forbidden);
        }
    }

    // Явная маршрутизация по префиксу: у каждого провайдера свой префикс
    // (`ollama/`, `openai/`, ...). Проверяем allowlist по ПОЛНОМУ имени
    // (как его видит клиент), а наружу отдаём уже срезанное.
    let mut explicit = None;
    let mut send_model = client_model.clone();
    if let Some(model) = &client_model {
        for (i, p) in cfg.providers.iter().enumerate() {
            if p.model_prefix.is_empty() {
                continue;
            }
            if let Some(stripped) = model.strip_prefix(&p.model_prefix) {
                if stripped.is_empty() {
                    return Err(AppError::BadRequest(
                        "После префикса провайдера должно быть имя модели",
                    ));
                }
                // `ollama/all` — то же, что «модель не указана»: запрос идёт
                // по приоритету, каждому провайдеру — его default-модель.
                if stripped.eq_ignore_ascii_case("all") {
                    explicit = None;
                    send_model = None;
                    break;
                }
                explicit = Some(i);
                send_model = Some(stripped.to_string());
                break;
            }
        }
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

    // Поле model в тело НЕ вставляем здесь: в dispatch оно подставляется
    // отдельно для каждого провайдера (клиентская или его default-модель).
    Ok(Prepared {
        value,
        model: client_model,
        send_model,
        stream,
        explicit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProviderKind;
    use std::{collections::HashSet, time::Duration};

    fn provider(name: &str, base: &str, kind: ProviderKind) -> ProviderConfig {
        ProviderConfig {
            name: name.into(),
            base: reqwest::Url::parse(base).unwrap(),
            api_key: Some("provider-key".into()),
            kind,
            model_prefix: format!("{name}/"),
            default_model: None,
        }
    }

    fn cfg(providers: Vec<ProviderConfig>, models: &[&str], cap: u64) -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            providers,
            client_keys: vec!["client-key-aaaaaaaaaaaaaaaa".into()],
            allowed_models: models.iter().map(|s| s.to_string()).collect::<HashSet<_>>(),
            max_output_tokens: cap,
            rate_per_minute: 60,
            max_concurrent: 4,
            request_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(10),
            python_bin: None,
            allow_http: false,
        }
    }

    fn single_cfg(models: &[&str], cap: u64) -> Config {
        cfg(
            vec![provider("primary", "https://api.example.com/v1", ProviderKind::OpenAi)],
            models,
            cap,
        )
    }

    fn cfg_with_ollama(models: &[&str], cap: u64, prefix: &str) -> Config {
        let mut ollama = provider("ollama", "http://127.0.0.1:11434", ProviderKind::Ollama);
        ollama.api_key = None;
        ollama.model_prefix = prefix.into();
        cfg(
            vec![
                provider("primary", "https://api.example.com/v1", ProviderKind::OpenAi),
                ollama,
            ],
            models,
            cap,
        )
    }

    #[tokio::test]
    async fn valid_request_passes() {
        let body = br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &single_cfg(&["gpt-4o-mini"], 100))
            .await
            .unwrap();
        assert_eq!(p.model.as_deref(), Some("gpt-4o-mini"));
        assert!(!p.stream);
        assert_eq!(p.explicit, None);
    }

    #[tokio::test]
    async fn max_tokens_is_clamped() {
        let body =
            br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"max_tokens":999999}"#;
        let c = single_cfg(&[], 512);
        let p = prepare_request(body, &c).await.unwrap();
        let v: Value =
            serde_json::from_slice(&p.body_for(&c.providers[0]).unwrap()).unwrap();
        assert_eq!(v["max_tokens"], 512);
    }

    #[tokio::test]
    async fn max_completion_tokens_is_clamped_too() {
        let body = br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":99999}"#;
        let c = single_cfg(&[], 512);
        let p = prepare_request(body, &c).await.unwrap();
        let v: Value =
            serde_json::from_slice(&p.body_for(&c.providers[0]).unwrap()).unwrap();
        assert_eq!(v["max_completion_tokens"], 512);
    }

    #[tokio::test]
    async fn model_allowlist_enforced() {
        let body = br#"{"model":"expensive","messages":[{"role":"user","content":"hi"}]}"#;
        assert!(matches!(
            prepare_request(body, &single_cfg(&["cheap"], 100)).await,
            Err(AppError::Forbidden)
        ));
    }

    #[tokio::test]
    async fn bad_bodies_rejected() {
        let c = single_cfg(&[], 100);
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
        assert!(prepare_request(body, &single_cfg(&[], 100)).await.is_err());
    }

    #[tokio::test]
    async fn stream_flag_detected() {
        let body = br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
        assert!(prepare_request(body, &single_cfg(&[], 100)).await.unwrap().stream);
    }

    // ---- маршрутизация по префиксу провайдера ----

    #[tokio::test]
    async fn ollama_prefix_routes_and_is_stripped() {
        let c = cfg_with_ollama(&["ollama/llama3"], 100, "ollama/");
        let body = br#"{"model":"ollama/llama3","messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &c).await.unwrap();
        assert_eq!(p.explicit, Some(1), "префикс ollama/ → индекс 1");
        assert_eq!(p.model.as_deref(), Some("ollama/llama3"));
        // наружу уходит срезанное имя
        let v: Value =
            serde_json::from_slice(&p.body_for(&c.providers[1]).unwrap()).unwrap();
        assert_eq!(v["model"], "llama3");
    }

    #[tokio::test]
    async fn prefixed_model_routes_to_its_own_provider() {
        let c = cfg(vec![
            provider("openai", "https://a.example.com/v1", ProviderKind::OpenAi),
            provider("ollama", "http://127.0.0.1:11434", ProviderKind::Ollama),
        ], &["openai/gpt-4o"], 100);
        let body = br#"{"model":"openai/gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &c).await.unwrap();
        assert_eq!(p.explicit, Some(0));
        let v: Value =
            serde_json::from_slice(&p.body_for(&c.providers[0]).unwrap()).unwrap();
        assert_eq!(v["model"], "gpt-4o");
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
    async fn non_prefixed_model_unaffected_by_prefixes() {
        let c = cfg_with_ollama(&[], 100, "ollama/");
        let body = br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &c).await.unwrap();
        assert_eq!(p.explicit, None, "без префикса — failover по приоритету");
        let v: Value =
            serde_json::from_slice(&p.body_for(&c.providers[0]).unwrap()).unwrap();
        assert_eq!(v["model"], "gpt-4o-mini");
    }

    #[tokio::test]
    async fn empty_prefix_disables_routing() {
        let mut c = cfg_with_ollama(&[], 100, "");
        c.providers[1].model_prefix = String::new();
        let body = br#"{"model":"llama3","messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &c).await.unwrap();
        assert_eq!(p.explicit, None);
    }

    #[tokio::test]
    async fn unknown_prefix_goes_by_priority() {
        // префикс ollama/ не сконфигурирован — модель уходит по приоритету как есть
        let c = single_cfg(&[], 100);
        let body = br#"{"model":"ollama/llama3","messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &c).await.unwrap();
        assert_eq!(p.explicit, None);
        let v: Value =
            serde_json::from_slice(&p.body_for(&c.providers[0]).unwrap()).unwrap();
        assert_eq!(v["model"], "ollama/llama3");
    }

    // ---- модель по умолчанию провайдера ----

    fn cfg_with_defaults(providers: Vec<ProviderConfig>) -> Config {
        cfg(providers, &[], 100)
    }

    #[tokio::test]
    async fn no_model_uses_provider_default() {
        let mut p1 = provider("primary", "https://api.example.com/v1", ProviderKind::OpenAi);
        p1.default_model = Some("gpt-4o-mini".into());
        let c = cfg_with_defaults(vec![p1]);

        // model нет вообще
        let body = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &c).await.unwrap();
        assert_eq!(p.model, None, "клиент не указывал модель");
        assert_eq!(p.send_model, None);
        let v: Value =
            serde_json::from_slice(&p.body_for(&c.providers[0]).unwrap()).unwrap();
        assert_eq!(v["model"], "gpt-4o-mini", "подставлена default-модель провайдера");
    }

    #[tokio::test]
    async fn empty_or_null_model_treated_as_missing() {
        let mut p1 = provider("primary", "https://api.example.com/v1", ProviderKind::OpenAi);
        p1.default_model = Some("gpt-4o-mini".into());
        let c = cfg_with_defaults(vec![p1]);

        for body in [
            br#"{"model":"","messages":[{"role":"user","content":"hi"}]}"#.as_slice(),
            br#"{"model":null,"messages":[{"role":"user","content":"hi"}]}"#.as_slice(),
        ] {
            let p = prepare_request(body, &c).await.unwrap();
            assert_eq!(p.model, None);
        }
        // не-строка — ошибка
        let bad = br#"{"model":42,"messages":[{"role":"user","content":"hi"}]}"#;
        assert!(prepare_request(bad, &c).await.is_err());
    }

    #[tokio::test]
    async fn model_all_uses_provider_default() {
        let mut p1 = provider("primary", "https://api.example.com/v1", ProviderKind::OpenAi);
        p1.default_model = Some("gpt-4o-mini".into());
        let c = cfg_with_defaults(vec![p1]);

        // "all" в любом регистре и с пробелами — «модель не указана»
        for body in [
            br#"{"model":"all","messages":[{"role":"user","content":"hi"}]}"#.as_slice(),
            br#"{"model":"ALL","messages":[{"role":"user","content":"hi"}]}"#.as_slice(),
            br#"{"model":" All ","messages":[{"role":"user","content":"hi"}]}"#.as_slice(),
        ] {
            let p = prepare_request(body, &c).await.unwrap();
            assert_eq!(p.model, None, "{:?} — считается «не указана»", body);
            assert_eq!(p.send_model, None);
            let v: Value =
                serde_json::from_slice(&p.body_for(&c.providers[0]).unwrap()).unwrap();
            assert_eq!(v["model"], "gpt-4o-mini", "подставлена default-модель провайдера");
        }
    }

    #[tokio::test]
    async fn prefixed_model_all_means_unspecified() {
        let c = cfg_with_ollama(&[], 100, "ollama/");

        // "ollama/all" — то же, что модель не указана: идём по приоритету
        let body = br#"{"model":"ollama/all","messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &c).await.unwrap();
        assert_eq!(p.explicit, None, "префикс+all НЕ закрепляет провайдера");
        assert_eq!(p.send_model, None);
    }

    #[tokio::test]
    async fn each_provider_gets_its_own_default() {
        let mut p1 = provider("openai", "https://a.example.com/v1", ProviderKind::OpenAi);
        p1.default_model = Some("gpt-4o-mini".into());
        let mut p2 = provider("ollama", "http://127.0.0.1:11434", ProviderKind::Ollama);
        p2.api_key = None;
        p2.default_model = Some("llama3".into());
        let c = cfg_with_defaults(vec![p1, p2]);

        let body = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &c).await.unwrap();
        let v1: Value =
            serde_json::from_slice(&p.body_for(&c.providers[0]).unwrap()).unwrap();
        let v2: Value =
            serde_json::from_slice(&p.body_for(&c.providers[1]).unwrap()).unwrap();
        assert_eq!(v1["model"], "gpt-4o-mini", "первому — его default");
        assert_eq!(v2["model"], "llama3", "второму — его default");
    }

    #[tokio::test]
    async fn provider_without_default_skipped_when_no_model() {
        let p1 = provider("primary", "https://api.example.com/v1", ProviderKind::OpenAi);
        let mut p2 = provider("ollama", "http://127.0.0.1:11434", ProviderKind::Ollama);
        p2.api_key = None;
        p2.default_model = Some("llama3".into());
        let c = cfg_with_defaults(vec![p1, p2]);

        let body = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &c).await.unwrap();
        // первый (без default) пропускается, тело собрать нельзя
        assert_eq!(p.body_for(&c.providers[0]), None);
        // второй обслужит
        let v: Value =
            serde_json::from_slice(&p.body_for(&c.providers[1]).unwrap()).unwrap();
        assert_eq!(v["model"], "llama3");
    }

    #[tokio::test]
    async fn no_model_without_any_default_is_rejected() {
        let c = cfg_with_defaults(vec![provider(
            "primary",
            "https://api.example.com/v1",
            ProviderKind::OpenAi,
        )]);
        let body = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &c).await.unwrap();
        assert_eq!(p.body_for(&c.providers[0]), None);
    }

    #[tokio::test]
    async fn no_model_passes_allowlist_and_clamps_still_apply() {
        let mut p1 = provider("primary", "https://api.example.com/v1", ProviderKind::OpenAi);
        p1.default_model = Some("gpt-4o-mini".into());
        let c = cfg(vec![p1], &["cheap"], 512);

        let body = br#"{"messages":[{"role":"user","content":"hi"}],"max_tokens":999999}"#;
        let p = prepare_request(body, &c).await.unwrap();
        let v: Value =
            serde_json::from_slice(&p.body_for(&c.providers[0]).unwrap()).unwrap();
        assert_eq!(v["max_tokens"], 512, "потолок токенов действует и без model");
    }

    #[tokio::test]
    async fn client_model_wins_over_default() {
        let mut p1 = provider("primary", "https://api.example.com/v1", ProviderKind::OpenAi);
        p1.default_model = Some("gpt-4o-mini".into());
        let c = cfg_with_defaults(vec![p1]);

        let body = br#"{"model":"user-model","messages":[{"role":"user","content":"hi"}]}"#;
        let p = prepare_request(body, &c).await.unwrap();
        let v: Value =
            serde_json::from_slice(&p.body_for(&c.providers[0]).unwrap()).unwrap();
        assert_eq!(v["model"], "user-model", "явно указанная модель сильнее default");
    }

    // ---- failover: какие статусы заставляют пробовать следующего ----

    #[test]
    fn failover_statuses() {
        for s in [401, 403, 404, 408, 429, 500, 502, 503, 504] {
            assert!(
                is_failover_status(StatusCode::from_u16(s).unwrap()),
                "HTTP {s} должен вызывать failover"
            );
        }
        for s in [400, 413, 422] {
            assert!(
                !is_failover_status(StatusCode::from_u16(s).unwrap()),
                "HTTP {s} не должен вызывать failover"
            );
        }
    }

    // ---- native-тела Ollama ----

    #[tokio::test]
    async fn ollama_native_body_valid_and_num_predict_clamped() {
        let c = cfg_with_ollama(&[], 100, "ollama/");
        let oc = c.ollama().unwrap().clone();
        let body = br#"{"model":"llama3","messages":[{"role":"user","content":"hi"}],"stream":true,"options":{"num_predict":99999}}"#;
        let out = ollama_prepare_body(body, &c, &oc).await.unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["options"]["num_predict"], 100);
    }

    #[tokio::test]
    async fn ollama_native_body_requires_model() {
        let c = cfg_with_ollama(&[], 100, "ollama/");
        let oc = c.ollama().unwrap().clone();
        let body = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
        assert!(ollama_prepare_body(body, &c, &oc).await.is_err());
        assert!(ollama_prepare_body(b"not json", &c, &oc).await.is_err());
    }

    #[tokio::test]
    async fn ollama_native_default_model_used_when_no_model() {
        // c default-моделью запрос без model проходит, модель подставлена
        let mut c = cfg_with_ollama(&[], 100, "ollama/");
        c.providers[1].default_model = Some("llama3".into());
        let oc = c.ollama().unwrap().clone();
        let body = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
        let out = ollama_prepare_body(body, &c, &oc).await.unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["model"], "llama3", "подставлена default-модель ollama");

        // пустая строка в model — тоже считается «не указана»
        let body = br#"{"model":"","messages":[{"role":"user","content":"hi"}]}"#;
        let out = ollama_prepare_body(body, &c, &oc).await.unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["model"], "llama3");

        // "all" (любой регистр) — тоже «не указана»
        let body = br#"{"model":"ALL","messages":[{"role":"user","content":"hi"}]}"#;
        let out = ollama_prepare_body(body, &c, &oc).await.unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["model"], "llama3");

        // явная модель сильнее default
        let body = br#"{"model":"qwen2.5","messages":[{"role":"user","content":"hi"}]}"#;
        let out = ollama_prepare_body(body, &c, &oc).await.unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["model"], "qwen2.5");
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
        let oc = c.ollama().unwrap().clone();
        let body = br#"{"model":"llama3","messages":[]}"#;
        assert!(ollama_prepare_body(body, &c, &oc).await.is_ok());

        // чужая модель не проходит
        let body = br#"{"model":"gemma2","messages":[]}"#;
        assert!(matches!(
            ollama_prepare_body(body, &c, &oc).await,
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
/// но с проверкой модели и заменой ключа. Тот же failover по приоритету:
/// провайдер без поддержки Images (например Ollama) вернёт 404/501,
/// и запрос уйдёт следующему.
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

    // 3. Базовая валидация JSON; model необязательна (пустая/"all" — тоже
    //    «не указана») — без неё берётся default-модель провайдера
    //    (см. dispatch_with_failover).
    let value: Value = serde_json::from_slice(&body)
        .map_err(|_| AppError::BadRequest("Тело запроса должно быть корректным JSON"))?;

    let client_model: Option<String> = client_model_from(value.get("model"))?;

    if let Some(model) = &client_model {
        if !state.cfg.allowed_models.is_empty() && !state.cfg.allowed_models.contains(model) {
            return Err(AppError::Forbidden);
        }
    }

    // 4. Кандидаты — все провайдеры по приоритету.
    let candidates: Vec<usize> = (0..state.cfg.providers.len()).collect();
    if candidates.is_empty() {
        return Err(AppError::NotFound("Не настроен ни один провайдер"));
    }

    // 5-6. Запрос к провайдерам с failover: тело собирается отдельно для
    //    каждого провайдера с его default-моделью, если клиент не указал model.
    let prepared = Prepared {
        value,
        model: client_model.clone(),
        send_model: client_model.clone(),
        stream: false,
        explicit: None,
    };
    let dispatched = dispatch_with_failover(
        &state,
        &candidates,
        Endpoint::Images,
        &prepared,
        "application/json",
        true,
    )
    .await?;

    // 7-8. Чтение ответа (изображения в base64 могут быть большими)
    let (bytes, provider_idx, content_type) = match dispatched {
        Dispatched::Passthrough(resp) => return Ok(resp),
        Dispatched::Upstream { response: upstream, permit: _permit, provider } => {
            let content_type = upstream
                .headers()
                .get(header::CONTENT_TYPE)
                .cloned()
                .unwrap_or_else(|| HeaderValue::from_static("application/json"));
            let bytes = read_capped(upstream, MAX_IMAGE_RESPONSE_BYTES).await?;
            (bytes, provider, content_type)
        }
    };

    // Модель, реально ушедшая провайдеру: клиентская или его default.
    let served_model = client_model
        .clone()
        .or_else(|| state.cfg.providers[provider_idx].default_model.clone())
        .unwrap_or_else(|| "<нет>".into());

    tracing::info!(
        client,
        model = %served_model,
        requested = %prepared.model.as_deref().unwrap_or("<не указана>"),
        provider = %state.cfg.providers[provider_idx].name,
        ms = started.elapsed().as_millis() as u64,
        "image generation completed"
    );

    Ok(([(header::CONTENT_TYPE, content_type)], bytes).into_response())
}
