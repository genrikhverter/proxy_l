//! Конфигурация прокси.
//!
//! Правило: все секреты и настройки приходят из переменных окружения.
//! Ничего не хардкодим, при ошибке конфигурации падаем сразу при старте (fail fast),
//! а не в момент первого запроса пользователя.
//!
//! Провайдеры задаются СПИСКОМ С ПРИОРИТЕТОМ. Приоритет = порядок в списке:
//! если провайдер не отвечает (сеть, таймаут, 5xx, 429, отвергнутый ключ),
//! запрос автоматически уходит следующему по приоритету.
//!
//! Два способа задать список:
//!
//! 1. `UPSTREAMS` — единая строка, записи через запятую, поля через `|`:
//!
//! ```text
//! UPSTREAMS="openai|https://api.openai.com/v1|sk-xxx, ollama|http://127.0.0.1:11434|, vllm|http://192.168.1.10:8000/v1|token"
//! ```
//!
//! Формат записи: `имя|base_url[|api_key][|ollama]`.
//! * пустой `api_key` (или пропущенное поле) = запрос без Authorization
//!   (локальная Ollama так и работает — отдельные настройки ей не нужны);
//! * провайдер с именем `ollama` (или с явным 4-м полем `ollama`) дополнительно
//!   получает native-эндпоинты `/api/*` (NDJSON-стримы, `/api/tags`, ...);
//! * модель с префиксом `имя/` (например `ollama/llama3`, `openai/gpt-4o`)
//!   маршрутизируется к этому провайдеру явно, минуя приоритет;
//! * запрос без префикса идёт первому живому провайдеру по порядку.
//!
//! 2. Обратная совместимость: старые переменные `UPSTREAM_BASE_URL` +
//!    `UPSTREAM_API_KEY` задают провайдера `primary`, а Ollama включается
//!    автоматически на `http://127.0.0.1:11434` (никаких `OLLAMA_*` указывать
//!    не нужно; старые переменные `OLLAMA_BASE_URL`, `OLLAMA_API_KEY`,
//!    `OLLAMA_MODEL_PREFIX`, `OLLAMA_ENABLED=0` продолжают работать).
//!
//! Запросы к локальным провайдерам ходят по HTTP — это нормально для localhost.
//! Для http к НЕ-loopback хостам включите `ALLOW_HTTP_UPSTREAM=1`.

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

/// Тип провайдера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// OpenAI-совместимый API (`/v1/chat/completions`, `/v1/models`).
    OpenAi,
    /// Ollama: дополнительно к OpenAI-совместимому `/v1/...` умеет
    /// native-эндпоинты `/api/*` (стрим NDJSON, `/api/tags`, ...).
    Ollama,
}

/// Один провайдер из общего списка.
///
/// Все провайдеры унифицированы: прокси говорит с каждым по
/// OpenAI-совместимому протоколу (`{base}/chat/completions`), разница только в
/// `kind` (native `/api/*` у Ollama) и в наличии ключа. Локальная Ollama —
/// обычный провайдер без ключа, никаких отдельных настроек не требуется.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// Короткое имя для логов и префикса моделей (`ollama/llama3`).
    pub name: String,
    /// Корневой URL провайдера. Для OpenAI-совместимых обычно с `/v1`
    /// (например `https://api.openai.com/v1`), для Ollama — корень без `/v1`.
    pub base: Url,
    /// Ключ провайдера. `None` = Authorization не отправляется вовсе
    /// (локальная Ollama, открытый vLLM и т.п.).
    pub api_key: Option<String>,
    /// Тип протокола (влияет на native `/api/*` и `/v1/models`).
    pub kind: ProviderKind,
    /// Префикс моделей для явной маршрутизации из `/v1/chat/completions`:
    /// запрос с моделью `ollama/llama3` уходит этому провайдеру как `llama3`.
    /// По умолчанию `{имя}/`.
    pub model_prefix: String,
}

impl ProviderConfig {
    /// URL OpenAI-совместимого эндпоинта чата. У Ollama `/v1/...` живёт под
    /// корнем (прокси добавляет `/v1` сам), у остальных `/v1` входит в base.
    /// Путь строим САМИ из константы — клиент не управляет URL.
    pub fn chat_completions_url(&self) -> Url {
        match self.kind {
            ProviderKind::Ollama => join_path(&self.base, "v1/chat/completions"),
            ProviderKind::OpenAi => join_path(&self.base, "chat/completions"),
        }
    }

    /// URL OpenAI-совместимого эндпоинта генерации изображений.
    pub fn images_url(&self) -> Url {
        match self.kind {
            ProviderKind::Ollama => join_path(&self.base, "v1/images/generations"),
            ProviderKind::OpenAi => join_path(&self.base, "images/generations"),
        }
    }

    /// URL списка моделей: у Ollama native `/api/tags`, у остальных
    /// OpenAI-совместимый `base + /models`.
    pub fn models_url(&self) -> Url {
        match self.kind {
            ProviderKind::Ollama => join_path(&self.base, "api/tags"),
            ProviderKind::OpenAi => join_path(&self.base, "models"),
        }
    }

    /// URL native-эндпоинта: base + path (`/api/chat`, `/api/generate`, ...).
    /// Имеет смысл только для `ProviderKind::Ollama`.
    /// Путь строим САМИ из константы — клиент не управляет URL.
    pub fn api_url(&self, path: &str) -> Url {
        join_path(&self.base, path)
    }
}

/// Склеивает путь базового URL с относительным путём эндпоинта.
fn join_path(base: &Url, path: &str) -> Url {
    let mut url = base.clone();
    let joined =
        format!("{}/{}", url.path().trim_end_matches('/'), path.trim_start_matches('/'));
    url.set_path(&joined);
    url
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Куда биндимся. По умолчанию только loopback — наружу открывать осознанно.
    pub listen: SocketAddr,
    /// Провайдеры В ПОРЯДКЕ ПРИОРИТЕТА: индекс 0 — самый приоритетный.
    /// При недоступности одного запрос уходит следующему.
    pub providers: Vec<ProviderConfig>,
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
    /// Сколько запросов к ОДНОМУ провайдеру может выполняться одновременно
    /// (у каждого провайдера свой пул слотов).
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
}

impl Config {
    /// Первый в списке провайдер типа Ollama (для native-эндпоинтов `/api/*`).
    pub fn ollama(&self) -> Option<&ProviderConfig> {
        self.providers.iter().find(|p| p.kind == ProviderKind::Ollama)
    }

    /// Индекс первого провайдера типа Ollama.
    pub fn ollama_index(&self) -> Option<usize> {
        self.providers.iter().position(|p| p.kind == ProviderKind::Ollama)
    }

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

        // http к чужим хостам — только осознанно: ключ/промпты уйдут по сети
        // открытым текстом. Для loopback http разрешён всегда.
        let allow_http = env_flag("ALLOW_HTTP_UPSTREAM");

        // ---- Список провайдеров с приоритетами ----
        let providers = match env::var("UPSTREAMS") {
            Ok(spec) if !spec.trim().is_empty() => parse_upstreams(&spec, allow_http)?,
            _ => legacy_providers(allow_http)?,
        };
        if providers.is_empty() {
            return Err(
                "не настроен ни один провайдер: задайте UPSTREAMS \
                 (или UPSTREAM_BASE_URL + UPSTREAM_API_KEY)"
                    .into(),
            );
        }

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
            providers,
            client_keys,
            allowed_models,
            max_output_tokens,
            rate_per_minute,
            max_concurrent,
            request_timeout: Duration::from_secs(timeout_secs),
            idle_timeout: Duration::from_secs(idle_secs),
            python_bin,
            allow_http,
        })
    }
}

/// Разбор `UPSTREAMS`: записи через запятую, поля через `|`.
///
/// Формат записи: `имя|base_url[|api_key][|ollama]`.
/// Порядок записей = приоритет (первая запись — самый приоритетный провайдер).
fn parse_upstreams(spec: &str, allow_http: bool) -> Result<Vec<ProviderConfig>, String> {
    let mut out = Vec::new();

    for (n, entry) in spec.split(',').map(str::trim).filter(|e| !e.is_empty()).enumerate() {
        let where_ = format!("UPSTREAMS, запись №{}", n + 1);
        let fields: Vec<&str> = entry.split('|').map(str::trim).collect();
        if fields.len() < 2 || fields.len() > 4 {
            return Err(format!(
                "{where_}: ожидается формат имя|base_url[|api_key][|ollama], получено «{entry}»"
            ));
        }

        let name = fields[0];
        if name.is_empty()
            || name.len() > 32
            || !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        {
            return Err(format!(
                "{where_}: имя провайдера «{name}» некорректно — нужны строчные латинские \
                 буквы, цифры, «-» или «_», не длиннее 32 символов"
            ));
        }
        if out.iter().any(|p: &ProviderConfig| p.name == name) {
            return Err(format!("{where_}: провайдер «{name}» указан дважды"));
        }

        let base = validate_base_url(fields[1], allow_http)
            .map_err(|e| format!("{where_} (провайдер «{name}»): {e}"))?;

        // Тип: явное 4-е поле `ollama` или имя провайдера `ollama`.
        let kind = match fields.get(3) {
            None => {
                if name == "ollama" {
                    ProviderKind::Ollama
                } else {
                    ProviderKind::OpenAi
                }
            }
            Some(&"ollama") => ProviderKind::Ollama,
            Some(other) => {
                return Err(format!(
                    "{where_} (провайдер «{name}»): неизвестный тип «{other}», \
                     допустимо только «ollama»"
                ))
            }
        };

        // Ollama-провайдер — это корень без /v1 (native-пути /api/... клеятся к нему).
        // Частая ошибка: указать OpenAI-совместимый корень с /v1 — тогда получилось
        // бы /v1/api/chat. Отказываем сразу.
        if kind == ProviderKind::Ollama && base.path().trim_end_matches('/').ends_with("/v1") {
            return Err(format!(
                "{where_} (провайдер «{name}»): укажите КОРНЕВОЙ URL Ollama без /v1 \
                 (например http://127.0.0.1:11434); \
                 /v1/... и /api/... прокси добавит сам"
            ));
        }

        // Пустой ключ или пропущенное поле = запрос без Authorization.
        let api_key = fields.get(2).filter(|k| !k.is_empty()).map(|s| s.to_string());

        out.push(ProviderConfig {
            name: name.to_string(),
            base,
            api_key,
            kind,
            model_prefix: format!("{name}/"),
        });
    }

    Ok(out)
}

/// Обратная совместимость: конфигурация из старых переменных окружения.
///
/// `UPSTREAM_BASE_URL` + `UPSTREAM_API_KEY` → провайдер `primary`;
/// Ollama включается АВТОМАТИЧЕСКИ на `http://127.0.0.1:11434` без всяких
/// настроек — как наименее приоритетный (запасной) провайдер.
fn legacy_providers(allow_http: bool) -> Result<Vec<ProviderConfig>, String> {
    let upstream_api_key = env::var("UPSTREAM_API_KEY").unwrap_or_default();
    if upstream_api_key.trim().is_empty() {
        return Err(
            "UPSTREAM_API_KEY не задан. Задайте его вместе с UPSTREAM_BASE_URL \
             или перечислите провайдеров в UPSTREAMS"
                .into(),
        );
    }

    let base = env::var("UPSTREAM_BASE_URL").unwrap_or_else(|_| "https://api.openai.com/v1".into());
    let primary = ProviderConfig {
        name: "primary".into(),
        base: validate_base_url(&base, allow_http)?,
        api_key: Some(upstream_api_key),
        kind: ProviderKind::OpenAi,
        model_prefix: "primary/".into(),
    };

    let mut providers = vec![primary];

    // ---- Ollama: включена по умолчанию (обычно ключей нет, токены не платные).
    // Отдельных настроек не требует: дефолтный URL localhost подходит всем.
    if env_flag_off_by_default("OLLAMA_ENABLED") {
        let raw =
            env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:11434".into());
        if raw.trim().is_empty() {
            // явное отключение пустым значением
        } else {
            let base = validate_base_url(&raw, allow_http)?;
            if base.path().trim_end_matches('/').ends_with("/v1") {
                return Err(
                    "OLLAMA_BASE_URL: укажите КОРНЕВОЙ URL Ollama без /v1 \
                     (например http://127.0.0.1:11434); \
                     /v1/... и /api/... прокси добавит сам"
                        .into(),
                );
            }
            let api_key = env::var("OLLAMA_API_KEY").ok().filter(|k| !k.trim().is_empty());
            let model_prefix = env::var("OLLAMA_MODEL_PREFIX")
                .unwrap_or_else(|_| "ollama/".into())
                .trim()
                .to_string();
            providers.push(ProviderConfig {
                name: "ollama".into(),
                base,
                api_key,
                kind: ProviderKind::Ollama,
                model_prefix,
            });
        }
    }

    Ok(providers)
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

    #[test]
    fn provider_urls_are_built_by_us() {
        let p = ProviderConfig {
            name: "openai".into(),
            base: validate_base_url("https://api.openai.com/v1/", false).unwrap(),
            api_key: Some("k".into()),
            kind: ProviderKind::OpenAi,
            model_prefix: "openai/".into(),
        };
        assert_eq!(
            p.chat_completions_url().as_str(),
            "https://api.openai.com/v1/chat/completions"
        );
        assert_eq!(
            p.images_url().as_str(),
            "https://api.openai.com/v1/images/generations"
        );
        assert_eq!(p.models_url().as_str(), "https://api.openai.com/v1/models");

        let o = ProviderConfig {
            name: "ollama".into(),
            base: validate_base_url("http://127.0.0.1:11434", false).unwrap(),
            api_key: None,
            kind: ProviderKind::Ollama,
            model_prefix: "ollama/".into(),
        };
        assert_eq!(
            o.chat_completions_url().as_str(),
            "http://127.0.0.1:11434/v1/chat/completions"
        );
        assert_eq!(o.api_url("/api/chat").as_str(), "http://127.0.0.1:11434/api/chat");
        assert_eq!(o.api_url("api/generate").as_str(), "http://127.0.0.1:11434/api/generate");
        assert_eq!(o.models_url().as_str(), "http://127.0.0.1:11434/api/tags");
    }

    // ---- разбор UPSTREAMS ----

    #[test]
    fn upstreams_parsed_in_priority_order() {
        let spec = "openai|https://api.openai.com/v1|sk-xxx, \
                    vllm|http://192.168.1.10:8000/v1|token, \
                    ollama|http://127.0.0.1:11434|";
        let ps = parse_upstreams(spec, true).unwrap();
        assert_eq!(ps.len(), 3);
        // порядок = приоритет
        assert_eq!(ps[0].name, "openai");
        assert_eq!(ps[1].name, "vllm");
        assert_eq!(ps[2].name, "ollama");
        // ключи и типы
        assert_eq!(ps[0].api_key.as_deref(), Some("sk-xxx"));
        assert_eq!(ps[0].kind, ProviderKind::OpenAi);
        assert_eq!(ps[1].api_key.as_deref(), Some("token"));
        assert_eq!(ps[2].api_key, None, "пустой ключ = без Authorization");
        assert_eq!(ps[2].kind, ProviderKind::Ollama, "имя ollama задаёт тип");
        // префиксы по имени
        assert_eq!(ps[0].model_prefix, "openai/");
        assert_eq!(ps[2].model_prefix, "ollama/");
    }

    #[test]
    fn upstreams_explicit_ollama_kind_and_empty_key() {
        let ps =
            parse_upstreams("local|http://127.0.0.1:11434||ollama", false).unwrap();
        assert_eq!(ps[0].name, "local");
        assert_eq!(ps[0].kind, ProviderKind::Ollama);
        assert_eq!(ps[0].api_key, None);
        assert_eq!(ps[0].model_prefix, "local/");
    }

    #[test]
    fn upstreams_two_fields_ok() {
        let ps = parse_upstreams("ollama|http://127.0.0.1:11434", false).unwrap();
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].api_key, None);
        assert_eq!(ps[0].kind, ProviderKind::Ollama);
    }

    #[test]
    fn upstreams_bad_entries_rejected() {
        // нет URL
        assert!(parse_upstreams("openai", false).is_err());
        // слишком много полей
        assert!(parse_upstreams("a|http://x|k|ollama|extra", false).is_err());
        // плохое имя
        assert!(parse_upstreams("Bad Name|https://x/v1|k", false).is_err());
        assert!(parse_upstreams("|https://x/v1|k", false).is_err());
        // дубликат имени
        assert!(parse_upstreams("a|https://x/v1|k, a|https://y/v1|k", false).is_err());
        // неизвестный тип
        assert!(parse_upstreams("a|https://x/v1|k|foo", false).is_err());
        // ollama с /v1 в корне
        assert!(parse_upstreams("ollama|http://127.0.0.1:11434/v1|", false).is_err());
        // http на чужой хост без флага
        assert!(parse_upstreams("a|http://192.168.1.10:8000/v1|k", false).is_err());
        // пустая строка → пустой список (ошибка отдаётся выше, в from_env)
        assert!(parse_upstreams(" , ,", false).unwrap().is_empty());
    }

    #[test]
    fn config_ollama_helpers_find_first_ollama() {
        let cfg = Config {
            listen: "127.0.0.1:8080".parse().unwrap(),
            providers: vec![
                ProviderConfig {
                    name: "openai".into(),
                    base: validate_base_url("https://api.openai.com/v1", false).unwrap(),
                    api_key: Some("k".into()),
                    kind: ProviderKind::OpenAi,
                    model_prefix: "openai/".into(),
                },
                ProviderConfig {
                    name: "ollama".into(),
                    base: validate_base_url("http://127.0.0.1:11434", false).unwrap(),
                    api_key: None,
                    kind: ProviderKind::Ollama,
                    model_prefix: "ollama/".into(),
                },
            ],
            client_keys: vec!["c".into()],
            allowed_models: HashSet::new(),
            max_output_tokens: 100,
            rate_per_minute: 60,
            max_concurrent: 1,
            request_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(10),
            python_bin: None,
            allow_http: false,
        };
        assert_eq!(cfg.ollama().unwrap().name, "ollama");
        assert_eq!(cfg.ollama_index(), Some(1));
    }
}
