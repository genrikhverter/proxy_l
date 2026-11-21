//! Интеграционный тест failover: реальные HTTP-серверы в отдельных задачах.
//!
//! Проверяем:
//! 1. провайдер №1 отвечает 500 → запрос уходит провайдеру №2 → клиенту 200;
//! 2. провайдер №1 недоступен (connection refused) → провайдер №2 отвечает;
//! 3. не-фейловерная 4xx от первого провайдера отдаётся клиенту как есть;
//! 4. явный префикс модели направляет запрос заданному провайдеру.

use std::{collections::HashSet, net::SocketAddr, sync::{Arc, Mutex}, time::Duration};

use axum::{routing::post, Json, Router};
use llm_proxy::{
    build_router,
    config::{Config, ProviderConfig, ProviderKind},
    AppState,
};
use serde_json::{json, Value};

async fn mock_server(status: u16, body: Value) -> SocketAddr {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || async move { (axum::http::StatusCode::from_u16(status).unwrap(), Json(body.clone())) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn provider(name: &str, addr: &SocketAddr, kind: ProviderKind) -> ProviderConfig {
    // ВАЖНО: base OpenAI-совместимого провайдера содержит /v1
    let base = format!("http://{addr}/v1");
    ProviderConfig {
        name: name.into(),
        base: reqwest::Url::parse(&base).unwrap(),
        api_key: Some("provider-key".into()),
        kind,
        model_prefix: format!("{name}/"),
        default_model: None,
    }
}

async fn start_proxy(providers: Vec<ProviderConfig>) -> SocketAddr {
    let cfg = Arc::new(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        providers,
        client_keys: vec!["client-key-aaaaaaaaaaaaaaaa".into()],
        allowed_models: HashSet::new(),
        max_output_tokens: 100,
        rate_per_minute: 600,
        max_concurrent: 8,
        request_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        python_bin: None,
        allow_http: false,
    });
    let app = build_router(AppState::new(cfg).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

async fn chat(addr: SocketAddr, model: &str) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .bearer_auth("client-key-aaaaaaaaaaaaaaaa")
        .json(&json!({"model": model, "messages": [{"role": "user", "content": "hi"}]}))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json::<Value>().await.unwrap())
}

fn ok_body() -> Value {
    json!({"id": "x", "choices": [{"message": {"role": "assistant", "content": "ok"}}]})
}

fn err_body() -> Value {
    json!({"error": {"message": "boom", "type": "server_error"}})
}

#[tokio::test]
async fn server_error_fails_over_to_next_provider() {
    // №1 всегда 500, №2 отвечает 200 — приоритет ниже, но он живой
    let first = mock_server(500, err_body()).await;
    let second = mock_server(200, ok_body()).await;
    let proxy = start_proxy(vec![
        provider("first", &first, ProviderKind::OpenAi),
        provider("second", &second, ProviderKind::OpenAi),
    ])
    .await;

    let (status, body) = chat(proxy, "some-model").await;
    assert_eq!(status, 200, "failover должен привести к успеху: {body}");
    assert_eq!(body["choices"][0]["message"]["content"], "ok");
}

#[tokio::test]
async fn unreachable_provider_fails_over_to_next() {
    // «провайдер» на закрытом порту: connection refused
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let second = mock_server(200, ok_body()).await;
    let proxy = start_proxy(vec![
        provider("dead", &dead, ProviderKind::OpenAi),
        provider("alive", &second, ProviderKind::OpenAi),
    ])
    .await;

    let (status, body) = chat(proxy, "some-model").await;
    assert_eq!(status, 200, "недоступный провайдер пропускается: {body}");
    assert_eq!(body["choices"][0]["message"]["content"], "ok");
}

#[tokio::test]
async fn client_error_is_passed_through_without_failover() {
    // 400 — ошибка в самом запросе, повторять её на другом провайдере не нужно
    let first = mock_server(400, err_body()).await;
    let second = mock_server(200, ok_body()).await;
    let proxy = start_proxy(vec![
        provider("first", &first, ProviderKind::OpenAi),
        provider("second", &second, ProviderKind::OpenAi),
    ])
    .await;

    let (status, body) = chat(proxy, "some-model").await;
    assert_eq!(status, 400, "4xx отдаётся как есть, без failover: {body}");
}

#[tokio::test]
async fn explicit_prefix_goes_only_to_named_provider() {
    // №1 жив, но модель с префиксом second/ должна уйти именно ко второму
    let first = mock_server(200, json!({"id": "wrong", "choices": []})).await;
    let second = mock_server(200, json!({"id": "right", "choices": []})).await;
    let proxy = start_proxy(vec![
        provider("first", &first, ProviderKind::OpenAi),
        provider("second", &second, ProviderKind::OpenAi),
    ])
    .await;

    let (status, body) = chat(proxy, "second/my-model").await;
    assert_eq!(status, 200);
    assert_eq!(body["id"], "right", "префикс выбирает провайдера: {body}");
}

#[tokio::test]
async fn all_providers_down_returns_502() {
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let proxy = start_proxy(vec![
        provider("dead1", &dead, ProviderKind::OpenAi),
        provider("dead2", &dead, ProviderKind::OpenAi),
    ])
    .await;

    let (status, body) = chat(proxy, "some-model").await;
    assert_eq!(status, 502, "все провайдеры недоступны: {body}");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("2 провайдеров"));
}

// ---- модель по умолчанию провайдера (model= в UPSTREAMS) ----

/// Мок-сервер, ЗАПИСЫВАЮЩИЙ полученные тела: проверяем, какая модель ушла провайдеру.
async fn recording_mock(status: u16, body: Value) -> (SocketAddr, Arc<Mutex<Vec<Value>>>) {
    let received: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let rx = received.clone();
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |Json(v): Json<Value>| {
            let rx = rx.clone();
            let body = body.clone();
            async move {
                rx.lock().unwrap().push(v);
                (
                    axum::http::StatusCode::from_u16(status).unwrap(),
                    Json(body),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, received)
}

async fn chat_no_model(addr: SocketAddr) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .bearer_auth("client-key-aaaaaaaaaaaaaaaa")
        .json(&json!({"messages": [{"role": "user", "content": "hi"}]}))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json::<Value>().await.unwrap())
}

#[tokio::test]
async fn failover_without_model_uses_each_provider_default() {
    // №1 всегда 500; №2 жив. Клиент НЕ указал model — у каждого провайдера
    // своя default-модель, и второй должен получить именно СВОЮ.
    let (first, _) = recording_mock(500, err_body()).await;
    let (second, received) = recording_mock(200, ok_body()).await;

    let mut p1 = provider("first", &first, ProviderKind::OpenAi);
    p1.default_model = Some("first-default".into());
    let mut p2 = provider("second", &second, ProviderKind::OpenAi);
    p2.default_model = Some("second-default".into());
    let proxy = start_proxy(vec![p1, p2]).await;

    let (status, body) = chat_no_model(proxy).await;
    assert_eq!(status, 200, "failover без model должен привести к успеху: {body}");

    let got = received.lock().unwrap();
    assert_eq!(got.len(), 1, "запрос дошёл только до второго провайдера");
    assert_eq!(
        got[0]["model"], "second-default",
        "второму провайдеру подставлена ЕГО default-модель"
    );
}

#[tokio::test]
async fn provider_without_default_skipped_when_no_model() {
    // №1 жив, но без default-модели → из запроса без model он пропускается,
    // обслуживает №2 со своей default-моделью.
    let (first, first_received) = recording_mock(200, ok_body()).await;
    let (second, second_received) = recording_mock(200, ok_body()).await;

    let p1 = provider("nodefault", &first, ProviderKind::OpenAi); // default: None
    let mut p2 = provider("withdefault", &second, ProviderKind::OpenAi);
    p2.default_model = Some("second-default".into());
    let proxy = start_proxy(vec![p1, p2]).await;

    let (status, body) = chat_no_model(proxy).await;
    assert_eq!(status, 200, "обслуживает провайдер с default-моделью: {body}");
    assert!(
        first_received.lock().unwrap().is_empty(),
        "провайдер без default-модели не должен вызываться"
    );
    let got = second_received.lock().unwrap();
    assert_eq!(got[0]["model"], "second-default");
}

#[tokio::test]
async fn no_model_and_no_defaults_returns_400() {
    let first = mock_server(200, ok_body()).await;
    let proxy = start_proxy(vec![provider("first", &first, ProviderKind::OpenAi)]).await;

    let (status, body) = chat_no_model(proxy).await;
    assert_eq!(status, 400, "ни у одного провайдера нет default-модели: {body}");
    assert!(body["error"]["message"].as_str().unwrap().contains("model"));
}
