//! Конфигурация прокси.
//!
//! Правило: все секреты и настройки приходят из переменных окружения.
//! Ничего не хардкодим, при ошибке конфигурации падаем сразу при старте (fail fast),
//! а не в момент первого запроса пользователя.

use std::{collections::HashSet, env, net::SocketAddr, str::FromStr, time::Duration};

use reqwest::Url;

/// Максимальный размер тела запроса от клиента (1 МиБ).
/// Защищает от «заливки» гигантского промпта и исчерпания памяти.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Максимальный размер НЕстримингового ответа провайдера (16 МиБ).
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Сколько байт тела ошибки провайдера мы читаем (и, возможно, отдаём клиенту).
pub const MAX_ERROR_BODY_BYTES: usize = 4 * 1024;

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
    /// Разрешённые модели. Пустое множество = разрешены все (не рекомендуется).
    pub allowed_models: HashSet<String>,
    /// Потолок длины ответа: режем `max_tokens` / `max_completion_tokens`.
    pub max_output_tokens: u64,
    /// Лимит запросов на одного клиента в минуту (token bucket).
    pub rate_per_minute: u32,
    /// Сколько запросов к провайдеру может выполняться одновременно.
    pub max_concurrent: usize,
    /// Полный таймаут для обычных (не стриминговых) запросов.
    pub request_timeout: Duration,
    /// Максимальная пауза между кусками ответа (в том числе внутри стрима).
    /// Больше 60 секунд стоит ставить, если пользуетесь «думающими» моделями:
    /// они могут молчать до первого токена дольше минуты.
    pub idle_timeout: Duration,
    /// Путь к бинарнику Python для выполнения кода из промптов.
    /// Если не задан или пустой — блоки ```python оставляются как есть.
    pub python_bin: Option<String>,
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

        let base =
            env::var("UPSTREAM_BASE_URL").unwrap_or_else(|_| "https://api.openai.com/v1".into());
        let upstream_base = validate_base_url(&base)?;

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

/// Проверка базового URL провайдера.
///
/// Требования:
/// * только `https` (исключение — `http` на localhost, для локальной отладки);
/// * без логина/пароля, query и fragment — иначе легко получить неожиданную склейку URL.
fn validate_base_url(raw: &str) -> Result<Url, String> {
    let mut url =
        Url::parse(raw).map_err(|e| format!("UPSTREAM_BASE_URL: некорректный URL ({e})"))?;
    let host = url
        .host_str()
        .ok_or("UPSTREAM_BASE_URL: не указан хост")?
        .to_string();
    let is_loopback = matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]");

    match url.scheme() {
        "https" => {}
        "http" if is_loopback => {} // локальный vLLM / мок в тестах
        _ => {
            return Err(format!(
                "UPSTREAM_BASE_URL: схема «{}» запрещена. Нужен https (http допустим только для localhost), \
                 иначе ключ провайдера уйдёт по сети открытым текстом",
                url.scheme()
            ))
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("UPSTREAM_BASE_URL: не должен содержать логин/пароль".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("UPSTREAM_BASE_URL: не должен содержать ?query и #fragment".into());
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
        let u = validate_base_url("https://api.openai.com/v1/").unwrap();
        assert_eq!(u.as_str(), "https://api.openai.com/v1");
    }

    #[test]
    fn plain_http_to_remote_host_rejected() {
        assert!(validate_base_url("http://api.openai.com/v1").is_err());
    }

    #[test]
    fn http_localhost_allowed_for_debug() {
        assert!(validate_base_url("http://127.0.0.1:9000/v1").is_ok());
    }

    #[test]
    fn weird_urls_rejected() {
        assert!(validate_base_url("file:///etc/passwd").is_err());
        assert!(validate_base_url("https://user:pass@api.openai.com/v1").is_err());
        assert!(validate_base_url("https://api.openai.com/v1?x=1").is_err());
        assert!(validate_base_url("not an url").is_err());
    }

    #[test]
    fn endpoint_path_is_built_by_us() {
        let cfg = Config {
            listen: "127.0.0.1:8080".parse().unwrap(),
            upstream_base: validate_base_url("https://api.example.com/v1").unwrap(),
            upstream_api_key: "k".into(),
            client_keys: vec!["c".into()],
            allowed_models: HashSet::new(),
            max_output_tokens: 100,
            rate_per_minute: 60,
            max_concurrent: 1,
            request_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(10),
        };
        assert_eq!(
            cfg.chat_completions_url().as_str(),
            "https://api.example.com/v1/chat/completions"
        );
    }
}
