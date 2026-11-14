Вот обновленный, подробный `README.md` и инструкция по запуску, учитывающие новую функциональность выполнения Python-кода из промптов.

---

# LLM Proxy — "Безопасный" шлюз к LLM-провайдерам

Высокопроизводительный HTTP-прокси для OpenAI-совместимых API (OpenAI, OpenRouter, GenOffice, vLLM и др.). written in Rust.

## ✨ Ключевые возможности

- **Безопасность ключей**: Настоящий ключ провайдера (`UPSTREAM_API_KEY`) никогда не покидает сервер. Клиенты используют отдельные ключи с constant-time проверкой (защита от timing-атак).
- **Выполнение кода из промптов**: Автоматический поиск блоков `` ```python `` в сообщениях, выполнение через внешний интерпретатор и подстановка результата обратно в промпт **до** отправки провайдеру.
- **Защита от злоупотреблений**:
  - Token Bucket Rate Limiter на каждого клиента
  - Семафор конкурентности (честный backpressure, 503 при перегрузке)
  - Лимиты на размер тела запроса/ответа
  - Allowlist моделей
  - Clamp `max_tokens` / `max_completion_tokens`
- **Стриминг (SSE)**: Корректная поддержка с backpressure через ограниченный канал. Медленный клиент тормозит чтение у провайдера, память не растёт.
- **Безопасность сети**: Отключены редиректы (защита от SSRF и утечки токенов), валидация Base URL, разделение таймаутов для стримов и обычных запросов.
- **Graceful Shutdown**: Корректное завершение активных стримов при SIGTERM/Ctrl-C.
- **Fail-fast конфигурация**: Прокси не запустится с некорректными настройками.

## 📁 Структура проекта

```
src/
├── main.rs       # Точка входа, graceful shutdown
├── lib.rs        # AppState, роутер, health-check
├── config.rs     # Конфигурация из ENV, валидация URL
├── security.rs   # Аутентификация, rate limiter
└── proxy.rs      # Обработка запросов, санитизация, выполнение Python-кода
```

## 🚀 Быстрый старт

### 1. Требования

- Rust 1.85+
- Python 3.x (если используется выполнение кода)

### 2. Сборка

```bash
# Для разработки
cargo build

# Для продакшена
cargo build --release
```

### 3. Настройка переменных окружения

Создайте файл `.env` или экспортируйте переменные:

```bash
# === ОБЯЗАТЕЛЬНЫЕ ===

# Ключи клиентов (через запятую, минимум 16 символов каждый)
# Генерация: openssl rand -hex 32
export PROXY_API_KEYS="client-key-aaaaaaaaaaaaaaaa,client-key-bbbbbbbbbbbbbbbb"

# Настоящий ключ провайдера (никогда не передаётся клиентам)
export UPSTREAM_API_KEY="sk-your-real-provider-key"

# === ОПЦИОНАЛЬНЫЕ ===

# Адрес прослушивания (по умолчанию только loopback)
export PROXY_LISTEN="127.0.0.1:8080"

# Базовый URL провайдера (без /chat/completions!)
export UPSTREAM_BASE_URL="https://api.openai.com/v1"

# Разрешённые модели (пустое = все разрешены — ОПАСНО!)
export ALLOWED_MODELS="gpt-4o-mini,gpt-4o,claude-3.5-sonnet"

# Потолок выходных токенов
export MAX_OUTPUT_TOKENS=4096

# Лимит запросов на клиента в минуту
export RATE_LIMIT_PER_MIN=60

# Максимум одновременных запросов к провайдеру
export MAX_CONCURRENT=32

# Таймауты (секунды, диапазон 1–600)
export REQUEST_TIMEOUT_SECS=120
export UPSTREAM_IDLE_TIMEOUT_SECS=120

# === ВЫПОЛНЕНИЕ PYTHON-КОДА ===

# Путь к интерпретатору Python. Если не задан — блоки ```python пропускаются.
# ⚠️ В продакшене используйте изолированный интерпретатор!
export PYTHON_BIN="/usr/bin/python3"
```

### 4. Запуск

```bash
# Разработка
cargo run

# Продакшен
./target/release/llm-proxy
```

### 5. Проверка

```bash
# Health-check
curl http://127.0.0.1:8080/health
# {"status":"ok"}

# Обычный запрос
curl -X POST http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer client-key-aaaaaaaaaaaaaaaa" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Привет!"}],
    "max_tokens": 50
  }'

# Запрос с выполнением Python-кода
curl -X POST http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer client-key-aaaaaaaaaaaaaaaa" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{
      "role": "user",
      "content": "Вычисли факториал 10:\n\n```python\nimport math\nprint(math.factorial(10))\n```"
    }]
  }'
# Прокси выполнит код и отправит провайдеру:
# "Вычисли факториал 10:\n\n```\n3628800\n```"
```

## 🐍 Выполнение Python-кода из промптов

### Как это работает

1. Клиент отправляет запрос с блоками `` ```python ... ``` `` в поле `content` сообщений.
2. Прокси **до отправки провайдеру** находит все такие блоки.
3. Каждый блок выполняется через `PYTHON_BIN -c "<код>"`.
4. Блок заменяется на вывод интерпретатора в обычном code-fence: `` ```\n<вывод>\n``` ``.
5. Модифицированный запрос отправляется провайдеру.

### Ограничения и безопасность

| Параметр | Значение | Описание |
|----------|----------|----------|
| Таймаут выполнения | 30 секунд | Процесс убивается при превышении |
| Изоляция | **Отсутствует по умолчанию** | Используйте песочницу! |
| Сетевой доступ | Не ограничен | Ограничивайте через firewall/nsjail |
| Файловая система | Доступна процессу | Монтируйте read-only rootfs |

### ⚠️ БЕЗОПАСНОСТЬ: Изоляция Python

**НИКОГДА не запускайте `PYTHON_BIN=/usr/bin/python3` в продакшене без изоляции.** Клиенты могут выполнить произвольный код на вашем сервере.

Рекомендуемые варианты изоляции:

```bash
# Вариант 1: Docker (рекомендуется)
export PYTHON_BIN="/usr/local/bin/docker-python-sandbox"
# где docker-python-sandbox — скрипт:
# docker run --rm --network none --read-only \
#   --memory 256m --cpus 0.5 \
#   python:3.12-slim python -c "$@"

# Вариант 2: nsjail
export PYTHON_BIN="/usr/local/bin/nsjail-python"

# Вариант 3: Bubblewrap
export PYTHON_BIN="/usr/local/bin/bwrap-python"
```

### Поведение при ошибках

| Ситуация | Результат в промпте |
|----------|---------------------|
| Успешное выполнение | `` ```\n<stdout>\n``` `` |
| Ошибка выполнения | `` ```\n[ERROR exit=N]\n<stdout><stderr>\n``` `` |
| Таймаут (>30с) | `` ```\n[TIMEOUT] Код выполнялся дольше 30 секунд\n``` `` |
| Не удалось запустить | `` ```\n[SPAWN ERROR] ...\n``` `` |
| `PYTHON_BIN` не задан | Блоки `` ```python `` остаются без изменений |

## 🔧 Подключение разных провайдеров

Прокси совместим с любым OpenAI-совместимым API. Меняйте только `UPSTREAM_BASE_URL` и `UPSTREAM_API_KEY`:

```bash
# OpenAI
export UPSTREAM_BASE_URL="https://api.openai.com/v1"

# OpenRouter
export UPSTREAM_BASE_URL="https://openrouter.ai/api/v1"

# GenOffice / корпоративный шлюз
export UPSTREAM_BASE_URL="https://genoffice.company.com/v1"

# Локальный vLLM / Ollama
export UPSTREAM_BASE_URL="http://127.0.0.1:8000/v1"
```

> **Важно:** URL должен заканчиваться на `/v1`, а не на `/v1/chat/completions`. Прокси сам добавляет путь эндпоинта.

## 🏗️ Архитектура обработки запроса

```
Клиент → [Auth] → [Rate Limit] → [Parse JSON] → [Sanitize + Python Exec]
       → [Clamp max_tokens] → [Acquire Slot] → [Upstream Request]
       → [Stream / Read Response] → Клиент
```

Порядок проверок оптимизирован: дешёвые проверки (ключ, лимит, JSON) выполняются **до** дорогого сетевого запроса. Мусорный трафик не доходит до платного API.

## 📊 Переменные окружения (полная таблица)

| Переменная | Обязательна | По умолчанию | Описание |
|-----------|:-----------:|-------------|----------|
| `PROXY_API_KEYS` | ✅ | — | Ключи клиентов через запятую (≥16 симв.) |
| `UPSTREAM_API_KEY` | ✅ | — | Ключ провайдера |
| `PROXY_LISTEN` | | `127.0.0.1:8080` | Адрес прослушивания |
| `UPSTREAM_BASE_URL` | | `https://api.openai.com/v1` | Base URL провайдера |
| `ALLOWED_MODELS` | | *(все)* | Разрешённые модели через запятую |
| `MAX_OUTPUT_TOKENS` | | `4096` | Потолок max_tokens/max_completion_tokens |
| `RATE_LIMIT_PER_MIN` | | `60` | Лимит запросов/мин на клиента |
| `MAX_CONCURRENT` | | `32` | Макс одновременных запросов к провайдеру |
| `REQUEST_TIMEOUT_SECS` | | `120` | Таймаут нестриминговых запросов (1–600) |
| `UPSTREAM_IDLE_TIMEOUT_SECS` | | `120` | Idle-таймаут стримов (1–600) |
| `PYTHON_BIN` | | *(нет)* | Путь к Python-интерпретатору |
| `RUST_LOG` | | `info` | Уровень логирования (trace/debug/info/warn/error) |

## 🧪 Тесты

```bash
cargo test
```

Тесты покрывают: аутентификацию, rate limiter, валидацию JSON, clamp токенов, allowlist моделей, стриминг, обработку ошибок.

## ⚠️ Известные ограничения

1. **Python-код выполняется синхронно в рамках запроса**: Длительное выполнение (до 30с) блокирует слот конкурентности. При большом количестве code-execution запросов увеличьте `MAX_CONCURRENT`.
2. **Нет кэширования результатов выполнения кода**: Один и тот же блок `` ```python `` выполняется заново при каждом запросе.
3. **Вложенные fenced-блоки не поддерживаются**: Если внутри Python-кода есть `` ``` ``, парсинг может сработать некорректно.
4. **HTTP разрешён только для localhost**: Для внутренних сервисов используйте HTTPS или настройте TLS-терминацию перед прокси.

## 📄 Лицензия

MIT
