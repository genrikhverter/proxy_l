//! Интеграционные тесты: поднимаем «игрушечного» провайдера и настоящий прокси
//! на случайных портах и гоняем через них реальные HTTP-запросы.
//!
//! Запуск: `cargo test`

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use llm_proxy::{build_router, config::Config, AppState};
use serde_json::{json, Value};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_stream::wrappers::ReceiverStream;

const UPSTREAM_KEY: &str = "upstream-secret-key-1234567890";
const CLIENT_KEY: &str = "client-key-aaaaaaaaaaaaaaaa";
const OTHER_CLIENT_KEY: &str = "client-key-bbbbbbbbbbbbbbbb";

// ---------------------------------------------------------------------------
// Мок провайдера (заменяет OpenAI)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockState {
    /// Всё, что провайдер получил: заголовок Authorization и тело запроса.
    seen: Arc<Mutex<Vec<Value>>>,
    /// Куда отдать редирект для модели "redirect".
    redirect_to: Arc<String>,
}

async fn mock_chat(
    State(st): State<MockState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    st.seen
        .lock()
        .unwrap()
        .push(json!({"auth": auth, "body": body}));

    // Провайдер требует СВОЙ ключ. Если прокси подсунул клиентский — будет 401.
    if auth != format!("Bearer {UPSTREAM_KEY}") {
        // Реальный OpenAI в таком ответе показывает начало ключа — проверим, что прокси это скроет.
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": {"message": format!(
                "Incorrect API key provided: {}***. You can find your API key at ...",
                &UPSTREAM_KEY[..10]
            )}})),
        )
            .into_response();
    }

    match body["model"].as_str().unwrap_or("") {
        "boom" => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal stack trace at 10.0.0.5",
            )
                .into_response();
        }
        "invalid" => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": {"message": "Unknown parameter: temperature"}})),
            )
                .into_response();
        }
        "slow" => {
            tokio::time::sleep(Duration::from_secs(5)).await;
            return Json(json!({"ok": true})).into_response();
        }
        "redirect" => {
            return (
                StatusCode::FOUND,
                [(header::LOCATION, st.redirect_to.as_str())],
                "follow me",
            )
                .into_response();
        }
        _ => {}
    }

    if body["stream"].as_bool() == Some(true) {
        // SSE: три куска с паузами и финальный [DONE].
        let (tx, rx) = mpsc::channel::<Result<String, std::io::Error>>(4);
        tokio::spawn(async move {
            for i in 0..3 {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let chunk = format!(
                    "data: {{\"choices\":[{{\"delta\":{{\"content\":\"часть{i}\"}}}}]}}\n\n"
                );
                if tx.send(Ok(chunk)).await.is_err() {
                    return;
                }
            }
            let _ = tx.send(Ok("data: [DONE]\n\n".to_string())).await;
        });
        return (
            [(header::CONTENT_TYPE, "text/event-stream")],
            Body::from_stream(ReceiverStream::new(rx)),
        )
            .into_response();
    }

    Json(json!({
        "id": "chatcmpl-test",
        "model": body["model"],
        "choices": [{"message": {"role": "assistant", "content": "привет"}}],
    }))
    .into_response()
}

/// «Злой» сервер: если прокси пойдёт по редиректу, ключ утечёт сюда.
async fn evil_steal(
    State(seen): State<Arc<Mutex<Vec<String>>>>,
    headers: HeaderMap,
) -> &'static str {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    seen.lock().unwrap().push(auth);
    "stolen"
}

// ---------------------------------------------------------------------------
// Инфраструктура тестов
// ---------------------------------------------------------------------------

async fn spawn(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

struct TestEnv {
    proxy: String,
    upstream: String,
    seen: Arc<Mutex<Vec<Value>>>,
    stolen: Arc<Mutex<Vec<String>>>,
    client: reqwest::Client,
}

/// Поднимает мок-провайдера, «злой» сервер и прокси. Возвращает адреса и счётчики.
async fn setup(models: &[&str], per_minute: u32, timeout_secs: u64, upstream_key: &str) -> TestEnv {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let stolen = Arc::new(Mutex::new(Vec::new()));

    let evil = spawn(
        Router::new()
            .route("/steal", get(evil_steal))
            .with_state(stolen.clone()),
    )
    .await;

    let mock = MockState {
        seen: seen.clone(),
        redirect_to: Arc::new(format!("{evil}/steal")),
    };
    let upstream = spawn(
        Router::new()
            .route("/v1/chat/completions", post(mock_chat))
            .with_state(mock),
    )
    .await;

    let cfg = Arc::new(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream_base: reqwest::Url::parse(&format!("{upstream}/v1")).unwrap(),
        upstream_api_key: upstream_key.to_string(),
        client_keys: vec![CLIENT_KEY.to_string(), OTHER_CLIENT_KEY.to_string()],
        allowed_models: models.iter().map(|s| s.to_string()).collect::<HashSet<_>>(),
        max_output_tokens: 512,
        rate_per_minute: per_minute,
        max_concurrent: 8,
        request_timeout: Duration::from_secs(timeout_secs),
        idle_timeout: Duration::from_secs(30),
    });

    let proxy = spawn(build_router(AppState::new(cfg).unwrap())).await;

    TestEnv {
        proxy,
        upstream,
        seen,
        stolen,
        client: reqwest::Client::new(),
    }
}

impl TestEnv {
    /// Перезапускает прокси с другим лимитом одновременных запросов.
    async fn set_max_concurrent(&mut self, n: usize) {
        let cfg = Arc::new(Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream_base: reqwest::Url::parse(&format!("{}/v1", self.upstream)).unwrap(),
            upstream_api_key: UPSTREAM_KEY.to_string(),
            client_keys: vec![CLIENT_KEY.to_string(), OTHER_CLIENT_KEY.to_string()],
            allowed_models: HashSet::new(),
            max_output_tokens: 512,
            rate_per_minute: 60,
            max_concurrent: n,
            request_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
        });
        self.proxy = spawn(build_router(AppState::new(cfg).unwrap())).await;
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.proxy, path)
    }

    /// Запрос с валидным ключом клиента.
    fn post(&self, body: Value) -> reqwest::RequestBuilder {
        self.client
            .post(self.url("/v1/chat/completions"))
            .bearer_auth(CLIENT_KEY)
            .json(&body)
    }
}

fn chat_body(model: &str) -> Value {
    json!({"model": model, "messages": [{"role": "user", "content": "привет"}]})
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_is_public_and_leaks_nothing() {
    let env = setup(&[], 60, 10, UPSTREAM_KEY).await;
    let resp = env.client.get(env.url("/health")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.text().await.unwrap();
    assert_eq!(text, r#"{"status":"ok"}"#);
}

#[tokio::test]
async fn request_without_key_is_rejected_before_upstream() {
    let env = setup(&[], 60, 10, UPSTREAM_KEY).await;
    let resp = env
        .client
        .post(env.url("/v1/chat/completions"))
        .json(&chat_body("gpt-4o-mini"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(
        env.seen.lock().unwrap().is_empty(),
        "до провайдера доходить не должно"
    );
}

#[tokio::test]
async fn request_with_wrong_key_is_rejected() {
    let env = setup(&[], 60, 10, UPSTREAM_KEY).await;
    let resp = env
        .client
        .post(env.url("/v1/chat/completions"))
        .bearer_auth("wrong-key-aaaaaaaaaaaaaaaaaa")
        .json(&chat_body("gpt-4o-mini"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(env.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn happy_path_substitutes_server_key_and_clamps_max_tokens() {
    let env = setup(&["gpt-4o-mini"], 60, 10, UPSTREAM_KEY).await;
    let mut body = chat_body("gpt-4o-mini");
    body["max_tokens"] = json!(1_000_000);

    let resp = env.post(body).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let json: Value = resp.json().await.unwrap();
    assert_eq!(json["choices"][0]["message"]["content"], "привет");

    let seen = env.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    // Провайдер получил СВОЙ ключ, а не клиентский.
    assert_eq!(seen[0]["auth"], format!("Bearer {UPSTREAM_KEY}"));
    // И обрезанный max_tokens.
    assert_eq!(seen[0]["body"]["max_tokens"], 512);
}

#[tokio::test]
async fn disallowed_model_never_reaches_upstream() {
    let env = setup(&["cheap-model"], 60, 10, UPSTREAM_KEY).await;
    let resp = env.post(chat_body("gpt-4o")).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    assert!(env.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn invalid_json_is_rejected() {
    let env = setup(&[], 60, 10, UPSTREAM_KEY).await;
    let resp = env
        .client
        .post(env.url("/v1/chat/completions"))
        .bearer_auth(CLIENT_KEY)
        .header(header::CONTENT_TYPE, "application/json")
        .body("{это не json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    assert!(env.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn oversized_body_is_rejected_with_413() {
    let env = setup(&[], 60, 10, UPSTREAM_KEY).await;
    let huge = "x".repeat(2 * 1024 * 1024); // 2 МиБ при лимите 1 МиБ
    let resp = env
        .post(json!({"model": "m", "messages": [{"role": "user", "content": huge}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
    assert!(env.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unknown_paths_are_not_proxied() {
    let env = setup(&[], 60, 10, UPSTREAM_KEY).await;
    for path in ["/v1/embeddings", "/v1/models", "/", "/../../etc/passwd"] {
        let resp = env
            .client
            .post(env.url(path))
            .bearer_auth(CLIENT_KEY)
            .json(&chat_body("m"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404, "путь {path} не должен проксироваться");
    }
    assert!(env.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn streaming_is_forwarded_chunk_by_chunk() {
    let env = setup(&[], 60, 10, UPSTREAM_KEY).await;
    let mut body = chat_body("gpt-4o-mini");
    body["stream"] = json!(true);

    let started = Instant::now();
    let mut resp = env.post(body).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/event-stream"
    );

    let mut first_chunk_at = None;
    let mut text = String::new();
    let mut chunks = 0;
    while let Some(chunk) = resp.chunk().await.unwrap() {
        if first_chunk_at.is_none() {
            first_chunk_at = Some(started.elapsed());
        }
        chunks += 1;
        text.push_str(&String::from_utf8_lossy(&chunk));
    }
    let total = started.elapsed();

    assert!(text.contains("часть0"), "потерян первый кусок: {text}");
    assert!(text.contains("часть2"), "потерян последний кусок: {text}");
    assert!(text.contains("data: [DONE]"), "нет завершения SSE: {text}");
    assert!(
        chunks >= 2,
        "ответ приехал одним куском — значит буферизуется"
    );
    // Мок отдаёт куски по 200 мс. Первый должен прийти заметно раньше конца.
    assert!(
        first_chunk_at.unwrap() < total,
        "первый кусок {:?}, всего {:?}",
        first_chunk_at.unwrap(),
        total
    );
}

#[tokio::test]
async fn upstream_auth_error_does_not_leak_our_key() {
    // Прокси настроен с НЕВЕРНЫМ ключом провайдера.
    let env = setup(&[], 60, 10, "wrong-upstream-key").await;
    let resp = env.post(chat_body("gpt-4o-mini")).send().await.unwrap();
    assert_eq!(resp.status(), 502);
    let text = resp.text().await.unwrap();
    assert!(
        !text.contains("Incorrect API key"),
        "утекло тело ошибки провайдера: {text}"
    );
    assert!(
        !text.contains("wrong-upstream-key"),
        "утекло значение ключа: {text}"
    );
    assert!(
        !text.contains(&UPSTREAM_KEY[..10]),
        "утекла часть ключа: {text}"
    );
}

#[tokio::test]
async fn upstream_5xx_details_are_hidden() {
    let env = setup(&[], 60, 10, UPSTREAM_KEY).await;
    let resp = env.post(chat_body("boom")).send().await.unwrap();
    assert_eq!(resp.status(), 502);
    let text = resp.text().await.unwrap();
    assert!(
        !text.contains("stack trace"),
        "утекли внутренности провайдера: {text}"
    );
    assert!(!text.contains("10.0.0.5"));
}

#[tokio::test]
async fn upstream_4xx_validation_error_is_passed_through() {
    let env = setup(&[], 60, 10, UPSTREAM_KEY).await;
    let resp = env.post(chat_body("invalid")).send().await.unwrap();
    assert_eq!(resp.status(), 400);
    let text = resp.text().await.unwrap();
    assert!(
        text.contains("Unknown parameter"),
        "клиенту полезно видеть ошибку валидации: {text}"
    );
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let env = setup(&[], 60, 10, UPSTREAM_KEY).await;
    let resp = env.post(chat_body("redirect")).send().await.unwrap();
    assert_eq!(resp.status(), 502);
    assert!(
        env.stolen.lock().unwrap().is_empty(),
        "прокси пошёл по редиректу и отдал ключ чужому хосту!"
    );
}

#[tokio::test]
async fn slow_upstream_hits_timeout() {
    let env = setup(&[], 60, 1, UPSTREAM_KEY).await; // таймаут 1 с, мок спит 5 с
    let resp = env.post(chat_body("slow")).send().await.unwrap();
    assert_eq!(resp.status(), 504);
}

#[tokio::test]
async fn rate_limit_is_per_client() {
    let env = setup(&[], 3, 10, UPSTREAM_KEY).await; // 3 запроса в минуту

    for i in 0..3 {
        let resp = env.post(chat_body("m")).send().await.unwrap();
        assert_eq!(resp.status(), 200, "запрос {i} должен пройти");
    }

    let resp = env.post(chat_body("m")).send().await.unwrap();
    assert_eq!(resp.status(), 429);
    assert!(resp.headers().contains_key(header::RETRY_AFTER));

    // У второго клиента свой лимит — он не пострадал.
    let resp = env
        .client
        .post(env.url("/v1/chat/completions"))
        .bearer_auth(OTHER_CLIENT_KEY)
        .json(&chat_body("m"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn upstream_key_is_never_sent_to_client_in_headers() {
    let env = setup(&[], 60, 10, UPSTREAM_KEY).await;
    let resp = env.post(chat_body("m")).send().await.unwrap();
    for (name, value) in resp.headers() {
        let v = value.to_str().unwrap_or("");
        assert!(
            !v.contains(UPSTREAM_KEY),
            "ключ провайдера найден в заголовке {name}"
        );
    }
}

#[tokio::test]
async fn concurrency_limit_returns_503_when_all_slots_busy() {
    // Один слот, мок спит 5 секунд. Второй параллельный запрос должен получить 503.
    let mut env = setup(&[], 60, 10, UPSTREAM_KEY).await;
    env.set_max_concurrent(1).await;

    let first = env.post(chat_body("slow")).send();
    let (first_resp, second_resp) = tokio::join!(first, async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        env.post(chat_body("m")).send().await
    });

    assert_eq!(
        second_resp.unwrap().status(),
        503,
        "ожидали отказ по конкурентности"
    );
    assert_eq!(first_resp.unwrap().status(), 200);
}

#[tokio::test]
async fn streaming_request_holds_its_slot_until_the_end() {
    // Проверяем главный смысл канала в streaming_response: слот занят ВЕСЬ стрим.
    let mut env = setup(&[], 60, 10, UPSTREAM_KEY).await;
    env.set_max_concurrent(1).await;

    let mut body = chat_body("m");
    body["stream"] = json!(true);
    let mut stream = env.post(body).send().await.unwrap();
    assert_eq!(stream.status(), 200);

    // Дождёмся первого куска: стрим точно идёт прямо сейчас.
    assert!(stream.chunk().await.unwrap().is_some());

    let busy = env.post(chat_body("m")).send().await.unwrap();
    assert_eq!(busy.status(), 503, "слот должен быть занят идущим стримом");

    // Дочитываем стрим до конца — слот освобождается.
    while stream.chunk().await.unwrap().is_some() {}
    tokio::time::sleep(Duration::from_millis(100)).await;

    let free = env.post(chat_body("m")).send().await.unwrap();
    assert_eq!(
        free.status(),
        200,
        "после конца стрима слот должен освободиться"
    );
}
