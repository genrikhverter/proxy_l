//! Конфигурация прокси.
//!
//! Правило: все секреты и настройки приходят из переменных окружения.
//! Ничего не хардкодим, при ошибке конфигурации падаем сразу при старте (fail fast),
//! а не в момент первого запроса пользователя.
//!
//! Провайдеров два:
//! * основной — OpenAI-совместимый API (платный), `UPSTREAM_BASE_URL`;
//! * локальная Ollama — `OLLAMA_BASE_URL` (по умолчанию `http://127.0.0.1:11434`).
//!
//! Запросы к Ollama ходят по HTTP — это нормально для localhost. Для http к
//! НЕ-loopback хостам включите `ALLOW_HTTP_UPSTREAM=1`.

use std::{collections::HashSet, env, net::SocketAddr, str::FromStr, time::Duration};

use reqwest::Url;

/// Максимальный размер тела запроса для генерации изображений (10 МиБ).
/// Изображения в base64 требуют большего лимита, чем текстовые чаты.
pub const MAX_IMAGE_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Максимальный размер тела запроса от клиента (1 МиБ).
/// Защищает от «заливки» гигантского промпта и исчерпания памяти.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Максимальный размер НЕстримингового ответа провайдера (16 МиБ).
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Сколько байт тела ошибки провайдера мы читаем (и, возможно, отдаём клиенту).
pub const MAX_ERROR_BODY_BYTES: usize = 4 * 1024;

/// Настройки локальной Ollama.
///
/// Ollama одновременно умеет два API:
/// * native (`/api/chat`, `/api/generate`, ...) — стримит NDJSON;
/// * OpenAI-совместимый (`/v1/chat/completions`) — стримит SSE.
/// Прокси умеет оба (см. `proxy.rs`).
#[derive(Debug, Clone)]
pub struct OllamaConfig {
    /// Корневой URL Ollama БЕЗ `/v1` и без `/api/...`, например `http://127.0.0.1:11434`.
    pub base: Url,
    /// Ключ, если Ollama закрыта авторизацией (`OLLAMA_API_KEY`).
    /// Обычная локальная Ollama не требует ключа — тогда `None`.
    pub api_key: Option<String>,
    /// Префикс моделей для маршрутизации из `/v1/chat/completions`:
    /// запрос с моделью `ollama/llama3` уходит в Ollama как модель `llama3`.
    /// Пустая строка = через /v1 в Ollama не маршрутизировать (только /api/...).
    pub model_prefix: String,
}

impl OllamaConfig {
    /// URL native-эндпоинта: base + path (`/api/chat`, `/api/tags`, ...).
    /// Путь строим САМИ из константы — клиент не управляет URL.
    pub fn api_url(&self, path: &str) -> Url {
        let mut url = self.base.clone();
        let joined =
            format!("{}/{}", url.path().trim_end_matches('/'), path.trim_start_matches('/'));
        url.set_path(&joined);
        url
    }

    /// URL OpenAI-совместимого эндпоинта чата Ollama.
    pub fn chat_completions_url(&self) -> Url {
        self.api_url("/v1/chat/completions")
    }

    /// URL списка установленных моделей.
    pub fn tags_url(&self) -> Url {
        self.api_url("/api/tags")
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Куда биндимся. По умолчанию только loopback — наружу открывать осознанно.
    pub listen: SocketAddr,
    /// Базовый URL провайдера, например `https://api.openai.com/v1`.
    pub upstream_base: Url,
    /// НАСТОЯЩИЙ ключ провайдера. Живёт только здесь, клиенту не выдаётся никогда.
    pub upstream_api_key: String,
    /// Ключи, которые мы выдаём своим клиентам (по одному на команду/сервис).
    pub client_keys: Vec<String>,
    /// Разрешённые модели (пишутся так, как их указывает клиент, включая префикс ollama/).
    /// Пустое множество = разрешены все (не рекомендуется).
    pub allowed_models: HashSet<String>,
    /// Потолок длины ответа: режем `max_tokens` / `max_completion_tokens`
    /// и `options.num_predict` у Ollama.
    pub max_output_tokens: u64,
    /// Лимит запросов на одного клиента в минуту (token bucket).
    pub rate_per_minute: u32,
    /// Сколько запросов к провайдеру может выполняться одновременно.
    pub max_concurrent: usize,
    /// Полный таймаут для обычных (не стриминговых) запросов.
    pub request_timeout: Duration,
    /// Максимальная пауза между кусками ответа (в том числе внутри стрима).
    /// Больше 60 секунд стоит ставить, если пользуетесь «думающими» моделями:
    /// они могут молчать до первого токена дольше минуты. Холодный старт
    /// Ollama (загрузка модели в память) тоже может «молчать» долго.
    pub idle_timeout: Duration,
    /// Путь к бинарнику Python для выполнения кода из промптов.
    /// Если не задан или пустой — блоки ```python оставляются как есть.
    pub python_bin: Option<String>,
    /// Разрешить http:// к НЕ-loopback upstream-хостам (см. `ALLOW_HTTP_UPSTREAM`).
    pub allow_http: bool,
    /// Настройки Ollama. `None` = Ollama выключена (`OLLAMA_ENABLED=0`).
    pub ollama: Option<OllamaConfig>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let listen = env::var("PROXY_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        let listen: SocketAddr = listen.parse().map_err(|_| {
            format!("PROXY_LISTEN: ожидался адрес вида ip:port, получено «{listen}»")
        })?;

        let client_keys = split_list(&env::var("PROXY_API_KEYS").unwrap_or_default());
        if client_keys.is_empty() {
            return Err(
                "PROXY_API_KEYS не задан: прокси без аутентификации запускать нельзя".into(),
            );
        }
        if let Some(short) = client_keys.iter().find(|k| k.len() < 16) {
            return Err(format!(
                "PROXY_API_KEYS: ключ длиной {} симв. слишком короткий (минимум 16). \
                 Сгенерируйте: openssl rand -hex 32",
                short.len()
            ));
        }

        let upstream_api_key = env::var("UPSTREAM_API_KEY").unwrap_or_default();
        if upstream_api_key.trim().is_empty() {
            return Err("UPSTREAM_API_KEY не задан".into());
        }

        // http к чужим хостам — только осознанно: ключ/промпты уйдут по сети
        // открытым текстом. Для loopback http разрешён всегда.
        let allow_http = env_flag("ALLOW_HTTP_UPSTREAM");

        let base =
            env::var("UPSTREAM_BASE_URL").unwrap_or_else(|_| "https://api.openai.com/v1".into());
        let upstream_base = validate_base_url(&base, allow_http)?;

        let allowed_models: HashSet<String> =
            split_list(&env::var("ALLOWED_MODELS").unwrap_or_default())
                .into_iter()
                .collect();

        let max_output_tokens = parse_env::<u64>("MAX_OUTPUT_TOKENS", 4096)?;
        let rate_per_minute = parse_env::<u32>("RATE_LIMIT_PER_MIN", 60)?;
        let max_concurrent = parse_env::<usize>("MAX_CONCURRENT", 32)?;
        let timeout_secs = parse_env::<u64>("REQUEST_TIMEOUT_SECS", 120)?;
        let idle_secs = parse_env::<u64>("UPSTREAM_IDLE_TIMEOUT_SECS", 120)?;

        if max_output_tokens == 0 || rate_per_minute == 0 || max_concurrent == 0 {
            return Err(
                "MAX_OUTPUT_TOKENS, RATE_LIMIT_PER_MIN и MAX_CONCURRENT должны быть > 0".into(),
            );
        }
        if !(1..=600).contains(&timeout_secs) || !(1..=600).contains(&idle_secs) {
            return Err(
                "REQUEST_TIMEOUT_SECS и UPSTREAM_IDLE_TIMEOUT_SECS должны быть в диапазоне 1..=600"
                    .into(),
            );
        }

        let python_bin = match env::var("PYTHON_BIN") {
            Ok(v) if !v.trim().is_empty() => Some(v),
            _ => None,
        };

        // ---- Ollama: включена по умолчанию (ключей обычно нет, токены не платные) ----
        let ollama = if env_flag_off_by_default("OLLAMA_ENABLED") {
            let raw =
                env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:11434".into());
            if raw.trim().is_empty() {
                None // явное отключение пустым значением
            } else {
                let base = validate_base_url(&raw, allow_http)?;
                // Частая ошибка: указать OpenAI-совместимый корень с /v1 — тогда
                // native-пути склеились бы в /v1/api/chat. Отказываем сразу.
                if base.path().trim_end_matches('/').ends_with("/v1") {
                    return Err(
                        "OLLAMA_BASE_URL: укажите КОРНЕВОЙ URL Ollama без /v1 \
                         (например http://127.0.0.1:11434); \
                         /v1/... и /api/... прокси добавит сам"
                            .into(),
                    );
                }
                let api_key = env::var("OLLAMA_API_KEY")
                    .ok()
                    .filter(|k| !k.trim().is_empty());
                let model_prefix = env::var("OLLAMA_MODEL_PREFIX")
                    .unwrap_or_else(|_| "ollama/".into())
                    .trim()
                    .to_string();
                Some(OllamaConfig {
                    base,
                    api_key,
                    model_prefix,
                })
            }
        } else {
            None
        };

        Ok(Config {
            listen,
            upstream_base,
            upstream_api_key,
            client_keys,
            allowed_models,
            max_output_tokens,
            rate_per_minute,
            max_concurrent,
            request_timeout: Duration::from_secs(timeout_secs),
            idle_timeout: Duration::from_secs(idle_secs),
            python_bin,
            allow_http,
            ollama,
        })
    }

    /// Итоговый URL эндпоинта. Путь строим САМИ из константы:
    /// клиент не управляет URL, значит невозможен SSRF и «открытый прокси».
    pub fn chat_completions_url(&self) -> Url {
        let mut url = self.upstream_base.clone();
        let path = format!("{}/chat/completions", url.path().trim_end_matches('/'));
        url.set_path(&path);
        url
    }
}

/// Переменная-флаг: «1», «true», «yes», «on» (в любом регистре) = true, остальное = false.
fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Флаг «включено по умолчанию»: выключен, только если задан равным 0/false/no/off.
fn env_flag_off_by_default(name: &str) -> bool {
    !env::var(name)
        .map(|v| matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ))
        .unwrap_or(false)
}

/// Проверка базового URL провайдера.
///
/// Требования:
/// * `https` где угодно; `http` — только loopback или при `ALLOW_HTTP_UPSTREAM=1`
///   (self-hosted vLLM/Ollama в локальной сети);
/// * без логина/пароля, query и fragment — иначе легко получить неожиданную склейку URL.
fn validate_base_url(raw: &str, allow_http: bool) -> Result<Url, String> {
    let mut url =
        Url::parse(raw).map_err(|e| format!("некорректный URL «{raw}» ({e})"))?;
    let host = url.host_str().ok_or("не указан хост")?.to_string();
    let is_loopback = matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]");

    match url.scheme() {
        "https" => {}
        "http" if is_loopback => {} // локальный vLLM / Ollama / мок в тестах
        "http" if allow_http => {}  // осознанный выбор: self-hosted в LAN
        "http" => {
            return Err(format!(
                "схема http разрешена только для localhost. Для http к «{host}» \
                 установите ALLOW_HTTP_UPSTREAM=1 (ключ и промпты пойдут открытым текстом)"
            ))
        }
        other => {
            return Err(format!(
                "схема «{other}» запрещена. Нужен https (http допустим только для localhost)"
            ))
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL не должен содержать логин/пароль".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("URL не должен содержать ?query и #fragment".into());
    }

    // Нормализуем завершающий слэш, чтобы дальше склеивать путь предсказуемо.
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(&path);
    Ok(url)
}

/// "a, b ,, c" -> ["a", "b", "c"]
fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_env<T: FromStr>(name: &str, default: T) -> Result<T, String> {
    match env::var(name) {
        Ok(v) => v
            .trim()
            .parse::<T>()
            .map_err(|_| format!("{name}: не удалось разобрать значение «{v}»")),
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_ok_and_slash_normalized() {
        let u = validate_base_url("https://api.openai.com/v1/", false).unwrap();
        assert_eq!(u.as_str(), "https://api.openai.com/v1");
    }

    #[test]
    fn plain_http_to_remote_host_rejected() {
        assert!(validate_base_url("http://api.openai.com/v1", false).is_err());
        assert!(validate_base_url("http://192.168.1.10:11434", false).is_err());
    }

    #[test]
    fn http_remote_allowed_with_flag() {
        assert!(validate_base_url("http://192.168.1.10:11434", true).is_ok());
        // флаг не ослабляет остальные проверки
        assert!(validate_base_url("file:///etc/passwd", true).is_err());
        assert!(validate_base_url("http://u:p@192.168.1.10:11434", true).is_err());
    }

    #[test]
    fn http_localhost_allowed_for_debug() {
        assert!(validate_base_url("http://127.0.0.1:9000/v1", false).is_ok());
        assert!(validate_base_url("http://localhost:11434", false).is_ok());
    }

    #[test]
    fn weird_urls_rejected() {
        assert!(validate_base_url("file:///etc/passwd", false).is_err());
        assert!(validate_base_url("https://user:pass@api.openai.com/v1", false).is_err());
        assert!(validate_base_url("https://api.openai.com/v1?x=1", false).is_err());
        assert!(validate_base_url("not an url", false).is_err());
    }

    fn ollama_cfg() -> OllamaConfig {
        OllamaConfig {
            base: validate_base_url("http://127.0.0.1:11434", false).unwrap(),
            api_key: None,
            model_prefix: "ollama/".into(),
        }
    }

    #[test]
    fn ollama_urls_are_built_by_us() {
        let oc = ollama_cfg();
        assert_eq!(oc.api_url("/api/chat").as_str(), "http://127.0.0.1:11434/api/chat");
        assert_eq!(oc.api_url("api/generate").as_str(), "http://127.0.0.1:11434/api/generate");
        assert_eq!(
            oc.chat_completions_url().as_str(),
            "http://127.0.0.1:11434/v1/chat/completions"
        );
        assert_eq!(oc.tags_url().as_str(), "http://127.0.0.1:11434/api/tags");
    }

    fn cfg_fixture() -> Config {
        Config {
            listen: "127.0.0.1:8080".parse().unwrap(),
            upstream_base: validate_base_url("https://api.example.com/v1", false).unwrap(),
            upstream_api_key: "k".into(),
            client_keys: vec!["c".into()],
            allowed_models: HashSet::new(),
            max_output_tokens: 100,
            rate_per_minute: 60,
            max_concurrent: 1,
            request_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(10),
            python_bin: None,
            allow_http: false,
            ollama: None,
        }
    }

    #[test]
    fn endpoint_path_is_built_by_us() {
        let cfg = cfg_fixture();
        assert_eq!(
            cfg.chat_completions_url().as_str(),
            "https://api.example.com/v1/chat/completions"
        );
    }
}
