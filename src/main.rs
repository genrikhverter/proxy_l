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
        providers = cfg.providers.len(),
        models = if cfg.allowed_models.is_empty() { "любые (задайте ALLOWED_MODELS!)".to_string() } else { format!("{:?}", cfg.allowed_models) },
        http_upstreams_allowed = cfg.allow_http,
        "прокси запущен"
    );

    // Провайдеры в порядке приоритета: первый живой обрабатывает запрос,
    // остальные — резерв при недоступности/ошибках предыдущего.
    for (i, p) in cfg.providers.iter().enumerate() {
        tracing::info!(
            priority = i + 1,
            provider = %p.name,
            base = %p.base,
            kind = if p.kind == llm_proxy::config::ProviderKind::Ollama { "ollama (+ /api/*)" } else { "openai-compatible" },
            auth = p.api_key.is_some(),
            model_prefix = %p.model_prefix,
            "провайдер настроен"
        );
    }
    if cfg.ollama().is_none() {
        tracing::info!(
            "Ollama не настроена: native-эндпоинты /api/* отключены, \
             добавьте провайдера ollama в UPSTREAMS при необходимости"
        );
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
