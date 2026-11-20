//! Простой прокси к внешним LLM-провайдерам с приоритетным failover.
//!
//! Схема работы:
//!
//! ```text
//!   ваш клиент                 этот прокси                  провайдеры (по приоритету)
//!  (SDK, curl)                 llm-proxy                    1. primary   2. ollama  ...
//!      │                           │                                │
//!      │ POST /v1/chat/completions │                                │
//!      │ Authorization: Bearer     │                                │
//!      │   <КЛЮЧ_КЛИЕНТА>          │                                │
//!      ├──────────────────────────>│ 1. проверяем ключ клиента      │
//!      │                           │ 2. лимит запросов              │
//!      │                           │ 3. валидируем JSON и модель    │
//!      │                           │ 4. меняем ключ на НАСТОЯЩИЙ    │
//!      │                           ├───────────────────────────────>│ №1
//!      │                           │    не отвечает / 5xx / 429?    │
//!      │                           ├───────────────────────────────>│ №2
//!      │                           │<───────────────────────────────┤
//!      │<──────────────────────────┤ 5. отдаём ответ (в т.ч. SSE)   │
//! ```
//!
//! Смысл: настоящий ключ провайдера знает только сервер. Клиенты получают
//! отдельные «свои» ключи, которые можно отозвать, ограничить по модели и по частоте.
//!
//! Доступ унифицирован: все провайдеры — равноправные записи списка
//! `UPSTREAMS` (или старых переменных окружения), каждый общается по
//! OpenAI-совместимому протоколу. Ollama — обычный провайдер без ключа,
//! отдельных настроек не требует: по умолчанию она добавляется на
//! `http://127.0.0.1:11434` как запасной провайдер.
//!
//! Маршрутизация моделей:
//! * модель с префиксом `имя/` (например `ollama/llama3`) идёт ЗАДАННОМУ
//!   провайдеру (префикс срезается), без failover;
//! * модель без префикса идёт первому живому провайдеру по приоритету;
//!   при недоступности / 5xx / 429 / 404 / 401 / 403 — следующему по списку.
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

use config::{Config, ProviderKind};
use security::RateLimiter;

/// Общее состояние приложения. Клонируется дёшево: всё тяжёлое — под `Arc`.
/// `reqwest::Client` внутри содержит пул соединений, поэтому создаём его ОДИН раз
/// и переиспользуем (иначе на каждый запрос будет новый TLS-handshake).
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    pub limiter: RateLimiter,
    /// Пул слотов конкурентности НА КАЖДОГО провайдера (индексы совпадают с
    /// `cfg.providers`). Локальные модели Ollama грузятся в память, поэтому
    /// им отдаём половину от основного лимита.
    pub slots: Vec<Arc<Semaphore>>,
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

        let slots = cfg
            .providers
            .iter()
            .map(|p| {
                let n = match p.kind {
                    // Ollama обычно держит столько слотов, сколько моделей способна
                    // грузить одновременно; делим пополам от основного лимита.
                    ProviderKind::Ollama => (cfg.max_concurrent / 2).max(1),
                    ProviderKind::OpenAi => cfg.max_concurrent,
                };
                Arc::new(Semaphore::new(n))
            })
            .collect();

        Ok(Self {
            limiter: RateLimiter::new(cfg.rate_per_minute),
            slots,
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
    // Запросы уходят первому провайдеру типа Ollama из общего списка.
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
/// allowlist из конфига + модели каждого провайдера (с его префиксом `имя/`).
/// Список запрашивается с коротким таймаутом: недоступный провайдер просто
/// пропускается, эндпоинт не ломается.
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

    // Добавляем модели каждого провайдера с его префиксом — клиент указывает
    // их именно в таком виде в /v1/chat/completions.
    for (i, p) in state.cfg.providers.iter().enumerate() {
        if let Some(names) = proxy::provider_model_list(&state, i).await {
            for name in names {
                models.push(json!({
                    "id": format!("{}{}", p.model_prefix, name),
                    "object": "model",
                    "owned_by": p.name
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
    use config::{ProviderConfig, ProviderKind};

    fn provider(name: &str, base: &str, kind: ProviderKind) -> ProviderConfig {
        ProviderConfig {
            name: name.into(),
            base: reqwest::Url::parse(base).unwrap(),
            api_key: Some("provider-key".into()),
            kind,
            model_prefix: format!("{name}/"),
        }
    }

    fn test_state() -> AppState {
        let cfg = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            providers: vec![
                provider("openai", "https://api.example.com/v1", ProviderKind::OpenAi),
                provider("ollama", "http://127.0.0.1:11434", ProviderKind::Ollama),
            ],
            client_keys: vec!["client-key-aaaaaaaaaaaaaaaa".into()],
            allowed_models: std::collections::HashSet::new(),
            max_output_tokens: 100,
            rate_per_minute: 60,
            max_concurrent: 4,
            request_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(10),
            python_bin: None,
            allow_http: false,
        };
        AppState::new(Arc::new(cfg)).unwrap()
    }

    #[test]
    fn router_builds_with_several_providers() {
        let st = test_state();
        // слоты выдаются на каждого провайдера
        assert_eq!(st.slots.len(), 2);
        let _r = build_router(st);
    }

    #[test]
    fn ollama_slots_are_half_of_main_limit() {
        let st = test_state();
        assert_eq!(st.slots[1].available_permits(), 2); // 4 / 2
        assert_eq!(st.slots[0].available_permits(), 4);
    }
}
