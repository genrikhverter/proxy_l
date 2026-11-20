//! Точка входа: логи → конфигурация → HTTP-сервер → корректное завершение.

use std::{error::Error, sync::Arc};

use llm_proxy::{build_router, config::Config, AppState};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Логи в stderr. Уровень меняется через RUST_LOG (например RUST_LOG=debug).
    // Мы принципиально не логируем тела запросов/ответов и заголовки с ключами.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Конфигурация читается один раз при старте; при ошибке — сразу выходим.
    let cfg = Arc::new(Config::from_env()?);
    let state = AppState::new(cfg.clone())?;
    let app = build_router(state);

    let listener = TcpListener::bind(cfg.listen).await?;
    tracing::info!(
        listen = %cfg.listen,
        upstream = %cfg.upstream_base,
        models = if cfg.allowed_models.is_empty() { "любые (задайте ALLOWED_MODELS!)".to_string() } else { format!("{:?}", cfg.allowed_models) },
        http_upstreams_allowed = cfg.allow_http,
        "прокси запущен"
    );

    // Ollama: отдельная строка лога, чтобы было видно, куда пойдут запросы
    // с префиксом ollama/ и native-эндпоинты /api/*.
    match &cfg.ollama {
        Some(oc) => tracing::info!(
            ollama = %oc.base,
            model_prefix = %oc.model_prefix,
            auth = oc.api_key.is_some(),
            "Ollama включена: /api/* и модели с префиксом {} маршрутизируются в неё",
            oc.model_prefix
        ),
        None => tracing::info!("Ollama выключена (OLLAMA_ENABLED=0 или пустой OLLAMA_BASE_URL)"),
    }

    // Graceful shutdown: по Ctrl-C перестаём принимать новые соединения
    // и даём текущим доработать (важно для длинных стримов при деплое).
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("прокси остановлен");
    Ok(())
}

/// Ждём Ctrl-C (локально) или SIGTERM (Docker/Kubernetes).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("получен сигнал остановки, дожидаемся текущих запросов");
}
