//! Простой прокси к внешним LLM-провайдерам.
//!
//! Схема работы:
//!
//! ```text
//!   ваш клиент                 этот прокси                    провайдер
//!  (SDK, curl)                 llm-proxy                      (OpenAI и т.п.)
//!      │                           │                                │
//!      │ POST /v1/chat/completions │                                │
//!      │ Authorization: Bearer     │                                │
//!      │   <КЛЮЧ_КЛИЕНТА>          │                                │
//!      ├──────────────────────────>│ 1. проверяем ключ клиента      │
//!      │                           │ 2. лимит запросов              │
//!      │                           │ 3. валидируем JSON и модель    │
//!      │                           │ 4. меняем ключ на НАСТОЯЩИЙ    │
//!      │                           ├───────────────────────────────>│
//!      │                           │<───────────────────────────────┤
//!      │<──────────────────────────┤ 5. отдаём ответ (в т.ч. SSE)   │
//! ```
//!
//! Смысл: настоящий ключ провайдера знает только сервер. Клиенты получают
//! отдельные «свои» ключи, которые можно отозвать, ограничить по модели и по частоте.
//!
//! Провайдеры:
//! * основной (OpenAI-совместимый, платный) — `UPSTREAM_BASE_URL`;
//! * локальная Ollama — `OLLAMA_BASE_URL` (по умолчанию включена на localhost).
//!
//! Модель с префиксом `ollama/…` в `/v1/chat/completions` маршрутизируется в
//! Ollama (префикс срезается), всё остальное — к основному провайдеру.
//! Помимо этого, целиком проксируются native-эндпоинты Ollama `/api/chat`,
//! `/api/generate`, `/api/embeddings`, `/api/show`, `/api/tags`, `/api/version`.

pub mod config;
pub mod proxy;
pub mod security;

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, State},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tokio::sync::Semaphore;

use config::Config;
use security::RateLimiter;

/// Общее состояние приложения. Клонируется дёшево: всё тяжёлое — под `Arc`.
/// `reqwest::Client` внутри содержит пул соединений, поэтому создаём его ОДИН раз
/// и переиспользуем (иначе на каждый запрос будет новый TLS-handshake).
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    pub limiter: RateLimiter,
    /// Слоты конкурентности к основному (платному) провайдеру.
    pub slots: Arc<Semaphore>,
    /// Отдельные слоты к Ollama: локальные модели грузятся в память,
    /// у них свой (обычно меньший) предел параллелизма.
    pub ollama_slots: Arc<Semaphore>,
}

impl AppState {
    pub fn new(cfg: Arc<Config>) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            // Сколько ждём установку соединения (TCP + TLS).
            .connect_timeout(Duration::from_secs(10))
            // Максимальный простой между кусками ответа. Работает и для стрима:
            // «провайдер замолчал надолго» — рвём соединение, а не висим вечно.
            .read_timeout(cfg.idle_timeout)
            // КРИТИЧНО: не следуем редиректам. Иначе провайдер (или злоумышленник,
            // подсунувший редирект) уведёт запрос вместе с ключом на другой хост.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("llm-proxy/", env!("CARGO_PKG_VERSION")))
            .tcp_nodelay(true)
            .build()?;

        // Ollama обычно держит столько же слотов, сколько моделей способна
        // грузить одновременно; по умолчанию делим пополам от основного лимита.
        let ollama_concurrency = cfg
            .ollama
            .as_ref()
            .map(|_| (cfg.max_concurrent / 2).max(1))
            .unwrap_or(1);

        Ok(Self {
            limiter: RateLimiter::new(cfg.rate_per_minute),
            slots: Arc::new(Semaphore::new(cfg.max_concurrent)),
            ollama_slots: Arc::new(Semaphore::new(ollama_concurrency)),
            http,
            cfg,
        })
    }
}

/// Собираем маршруты.
///
/// Маршрутов строго перечисленное множество: прокси НЕ умеет «сходить по любому
/// пути». Это не открытый прокси, а узкий шлюз к известным эндпоинтам.
pub fn build_router(state: AppState) -> Router {
    // Роутер для чата (лимит 1 МиБ)
    let chat_routes = Router::new()
        .route("/v1/chat/completions", post(proxy::chat_completions))
        .route("/v1/chat/completions/", post(proxy::chat_completions))
        .layer(DefaultBodyLimit::max(config::MAX_BODY_BYTES));

    // Роутер для изображений (лимит 10 МиБ)
    let image_routes = Router::new()
        .route("/v1/images/generations", post(proxy::image_generations))
        .route("/v1/images/generations/", post(proxy::image_generations))
        .layer(DefaultBodyLimit::max(config::MAX_IMAGE_BODY_BYTES));

    // Native-эндпоинты Ollama (лимит 1 МиБ: это текст, не изображения).
    // Путь строим сами и передаём константой — клиент не управляет URL.
    let ollama_routes = Router::new()
        .route("/api/chat", post(proxy::ollama_chat))
        .route("/api/generate", post(proxy::ollama_generate))
        .route("/api/embeddings", post(proxy::ollama_embeddings))
        .route("/api/show", post(proxy::ollama_show))
        .route("/api/tags", get(proxy::ollama_tags))
        .route("/api/version", get(proxy::ollama_version))
        .route("/api/chat/", post(proxy::ollama_chat))
        .route("/api/generate/", post(proxy::ollama_generate))
        .route("/api/embeddings/", post(proxy::ollama_embeddings))
        .route("/api/show/", post(proxy::ollama_show))
        .route("/api/tags/", get(proxy::ollama_tags))
        .route("/api/version/", get(proxy::ollama_version))
        .layer(DefaultBodyLimit::max(config::MAX_BODY_BYTES));

    // Общие маршруты без лимита тела
    Router::new()
        .route("/health", get(health))
        .route("/v1/models", get(list_models))
        .route("/v1/models/", get(list_models))
        .route("/v1", get(api_root))
        .route("/v1/", get(api_root))
        .merge(chat_routes)
        .merge(image_routes)
        .merge(ollama_routes)
        .with_state(state)
}

/// Ответ для GET /v1 и /v1/
async fn api_root() -> Json<serde_json::Value> {
    Json(json!({
        "object": "list",
        "data": [],
        "message": "LLM Proxy is running. Use /v1/chat/completions, /v1/images/generations or /api/* (Ollama)."
    }))
}

/// Ответ для GET /v1/models:
/// allowlist из конфига + модели, установленные в Ollama (с префиксом ollama/).
/// Список Ollama кешируется на короткое время, чтобы не дёргать её на каждый запрос.
async fn list_models(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut models: Vec<serde_json::Value> = if state.cfg.allowed_models.is_empty() {
        // Если allowlist пуст — показываем заглушку
        vec![json!({"id": "all", "object": "model", "owned_by": "proxy"})]
    } else {
        state
            .cfg
            .allowed_models
            .iter()
            .map(|m| json!({"id": m, "object": "model", "owned_by": "proxy"}))
            .collect()
    };

    // Добавляем модели Ollama с её префиксом — клиент указывает их
    // именно в таком виде в /v1/chat/completions.
    if let Some(oc) = &state.cfg.ollama {
        if let Some(tags) = proxy::ollama_model_list(&state, oc).await {
            for name in tags {
                models.push(json!({
                    "id": format!("{}{}", oc.model_prefix, name),
                    "object": "model",
                    "owned_by": "ollama"
                }));
            }
        }
    }

    Json(json!({
        "object": "list",
        "data": models
    }))
}

/// Проверка живости для балансировщика/k8s. Никаких секретов не отдаёт.
async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "ok"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> AppState {
        let cfg = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream_base: reqwest::Url::parse("https://api.example.com/v1").unwrap(),
            upstream_api_key: "k".into(),
            client_keys: vec!["client-key-aaaaaaaaaaaaaaaa".into()],
            allowed_models: std::collections::HashSet::new(),
            max_output_tokens: 100,
            rate_per_minute: 60,
            max_concurrent: 4,
            request_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(10),
            python_bin: None,
            allow_http: false,
            ollama: None,
        };
        AppState::new(Arc::new(cfg)).unwrap()
    }

    #[test]
    fn router_builds_with_and_without_ollama() {
        // без Ollama
        let _r = build_router(test_state());
        // с Ollama
        let mut st = test_state();
        Arc::get_mut(&mut st.cfg).unwrap().ollama = Some(config::OllamaConfig {
            base: reqwest::Url::parse("http://127.0.0.1:11434").unwrap(),
            api_key: None,
            model_prefix: "ollama/".into(),
        });
        let _r2 = build_router(st);
    }
}
