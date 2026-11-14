//! Простой прокси к внешнему LLM-провайдеру.
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
    pub slots: Arc<Semaphore>,
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

        Ok(Self {
            limiter: RateLimiter::new(cfg.rate_per_minute),
            slots: Arc::new(Semaphore::new(cfg.max_concurrent)),
            http,
            cfg,
        })
    }
}

/// Собираем маршруты.
///
/// Маршрутов ровно два: прокси НЕ умеет «сходить по любому пути».
/// Это не открытый прокси, а узкий шлюз к одному платному эндпоинту.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/chat/completions", post(proxy::chat_completions))
        .route("/v1/chat/completions/", post(proxy::chat_completions))
        // Эндпоинт списка моделей (требуется для проверки подключения в Craft Anything)
        .route("/v1/models", get(list_models))
        .route("/v1/models/", get(list_models))
        // Корневой путь /v1/ — некоторые клиенты пингуют его
        .route("/v1", get(api_root))
        .route("/v1/", get(api_root))
        // Ограничение размера тела: больше 1 МиБ -> автоматический 413, тело не читается в память.
        .layer(DefaultBodyLimit::max(config::MAX_BODY_BYTES))
        .with_state(state)
}

/// Ответ для GET /v1 и /v1/
async fn api_root() -> Json<serde_json::Value> {
    Json(json!({
        "object": "list",
        "data": [],
        "message": "LLM Proxy is running. Use /v1/chat/completions for requests."
    }))
}

/// Ответ для GET /v1/models — возвращаем allowed_models из конфига
async fn list_models(State(state): State<AppState>) -> Json<serde_json::Value> {
    let models: Vec<serde_json::Value> = if state.cfg.allowed_models.is_empty() {
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

    Json(json!({
        "object": "list",
        "data": models
    }))
}

/// Проверка живости для балансировщика/k8s. Никаких секретов не отдаёт.
async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "ok"}))
}
