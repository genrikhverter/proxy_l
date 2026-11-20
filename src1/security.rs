//! Безопасность: проверка клиентского ключа и лимит запросов.
//!
//! Здесь два простых механизма:
//! 1. `authenticate` — пускаем только своих, сравнивая токены за постоянное время;
//! 2. `RateLimiter`  — «ведро токенов» на каждого клиента, чтобы один клиент
//!    не сжёг весь бюджет и не устроил DoS.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

use axum::http::HeaderValue;
use subtle::ConstantTimeEq;

use crate::proxy::AppError;

/// Достаёт `Authorization: Bearer <ключ>` и ищет ключ среди разрешённых.
/// Возвращает НОМЕР клиента (0, 1, 2...) — это его идентификатор для логов и лимитов.
/// Сам ключ мы нигде не сохраняем и не логируем.
pub fn authenticate(header: Option<&HeaderValue>, keys: &[String]) -> Result<usize, AppError> {
    let raw = header
        .and_then(|h| h.to_str().ok()) // не-ASCII в заголовке -> сразу отказ
        .ok_or(AppError::Unauthorized)?;

    // По RFC схема аутентификации регистронезависима: "Bearer" == "bearer".
    let (scheme, token) = raw.split_once(' ').ok_or(AppError::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(AppError::Unauthorized);
    }
    let token = token.trim();

    // Сравниваем со ВСЕМИ ключами и не выходим из цикла досрочно:
    // время ответа не должно зависеть от того, какой по счёту ключ подошёл.
    let mut found = None;
    for (i, key) in keys.iter().enumerate() {
        if constant_time_eq(token.as_bytes(), key.as_bytes()) {
            found = Some(i);
        }
    }
    found.ok_or(AppError::Unauthorized)
}

/// Обычное `a == b` для строк сравнивает байты до первого несовпадения,
/// поэтому по времени ответа теоретически можно подбирать ключ посимвольно.
/// `subtle` сравнивает все байты независимо от результата.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Token bucket: у каждого клиента есть «ведро» ёмкостью `per_minute` токенов,
/// которое пополняется равномерно (per_minute / 60 токенов в секунду).
/// Один запрос = один токен. Пустое ведро -> 429.
///
/// Ключ — номер клиента, а не IP: за реверс-прокси все IP одинаковые,
/// а подделать `X-Forwarded-For` легко. Бонус: размер карты ограничен
/// числом выданных ключей, значит память не растёт бесконечно.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Inner>,
}

struct Inner {
    buckets: Mutex<HashMap<usize, Bucket>>,
    capacity: f64,
    refill_per_sec: f64,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl RateLimiter {
    pub fn new(per_minute: u32) -> Self {
        let capacity = per_minute as f64;
        Self {
            inner: Arc::new(Inner {
                buckets: Mutex::new(HashMap::new()),
                capacity,
                refill_per_sec: capacity / 60.0,
            }),
        }
    }

    pub fn allow(&self, client: usize) -> bool {
        self.allow_at(client, Instant::now())
    }

    /// Отдельный метод с явным «сейчас» — чтобы тесты были детерминированными.
    fn allow_at(&self, client: usize, now: Instant) -> bool {
        // std::sync::Mutex (не tokio): критическая секция крошечная и без await внутри,
        // поэтому блокировка дешевле и проще асинхронной.
        // Мьютекс не «отравлен» паникой? Если отравлен — данные всё равно целы, берём их.
        let mut buckets = self.inner.buckets.lock().unwrap_or_else(|e| e.into_inner());

        let bucket = buckets.entry(client).or_insert(Bucket {
            tokens: self.inner.capacity,
            updated: now,
        });

        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * self.inner.refill_per_sec).min(self.inner.capacity);
        bucket.updated = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    fn keys() -> Vec<String> {
        vec![
            "client-key-aaaaaaaaaaaaaaaa".to_string(),
            "client-key-bbbbbbbbbbbbbbbb".to_string(),
        ]
    }

    #[test]
    fn accepts_valid_bearer_and_returns_client_index() {
        let k = keys();
        assert_eq!(
            authenticate(Some(&hv("Bearer client-key-bbbbbbbbbbbbbbbb")), &k).unwrap(),
            1
        );
        assert_eq!(
            authenticate(Some(&hv("bearer client-key-aaaaaaaaaaaaaaaa")), &k).unwrap(),
            0
        );
    }

    #[test]
    fn rejects_missing_wrong_and_malformed() {
        let k = keys();
        assert!(authenticate(None, &k).is_err());
        assert!(authenticate(Some(&hv("Bearer wrong-key-aaaaaaaaaaaaaa")), &k).is_err());
        assert!(authenticate(Some(&hv("Basic client-key-aaaaaaaaaaaaaaaa")), &k).is_err());
        assert!(authenticate(Some(&hv("client-key-aaaaaaaaaaaaaaaa")), &k).is_err());
        // Префикс верного ключа не должен проходить.
        assert!(authenticate(Some(&hv("Bearer client-key-aaaa")), &k).is_err());
    }

    #[test]
    fn constant_time_compare_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn bucket_allows_burst_then_blocks_then_refills() {
        let limiter = RateLimiter::new(60); // 60/мин = 1 токен в секунду, всплеск до 60
        let t0 = Instant::now();

        for _ in 0..60 {
            assert!(limiter.allow_at(0, t0));
        }
        assert!(!limiter.allow_at(0, t0), "ведро должно опустеть");

        // Через 1 секунду появился ровно один токен.
        assert!(limiter.allow_at(0, t0 + Duration::from_secs(1)));
        assert!(!limiter.allow_at(0, t0 + Duration::from_secs(1)));

        // Другой клиент не страдает от чужого лимита.
        assert!(limiter.allow_at(1, t0));
    }

    #[test]
    fn bucket_never_exceeds_capacity_after_long_idle() {
        let limiter = RateLimiter::new(2);
        let t0 = Instant::now();
        let later = t0 + Duration::from_secs(3600);
        assert!(limiter.allow_at(0, later));
        assert!(limiter.allow_at(0, later));
        assert!(
            !limiter.allow_at(0, later),
            "накопить больше ёмкости нельзя"
        );
    }
}
