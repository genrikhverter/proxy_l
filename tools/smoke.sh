#!/usr/bin/env bash
# Быстрая проверка работающего прокси через curl.
#
#   1) python3 tools/mock_upstream.py                       # терминал 1
#   2) cargo run                                            # терминал 2 (с .env)
#   3) bash tools/smoke.sh                                  # терминал 3
#
# Переменные: PROXY (адрес прокси), KEY (ключ клиента).
set -u

PROXY="${PROXY:-http://127.0.0.1:8080}"
KEY="${KEY:-demo-client-key-0123456789abcdef}"
BODY='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"привет"}]}'

check() { # check <ожидаемый код> <описание> <curl-аргументы...>
  local want="$1" name="$2"; shift 2
  local got
  got=$(curl -s -o /tmp/smoke_body -w '%{http_code}' "$@")
  if [ "$got" = "$want" ]; then
    printf '  ✅ %-45s %s\n' "$name" "$got"
  else
    printf '  ❌ %-45s получили %s, ожидали %s\n     %s\n' "$name" "$got" "$want" "$(head -c 200 /tmp/smoke_body)"
  fi
}

echo "Проверки прокси на $PROXY"

# Готовим тело на 2 МиБ для проверки лимита размера.
{
  printf '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"'
  head -c 2097152 /dev/zero | tr '\0' 'x'
  printf '"}]}'
} > /tmp/smoke_big.json

check 200 "health без ключа" "$PROXY/health"

check 401 "без ключа -> 401" -X POST "$PROXY/v1/chat/completions" \
  -H 'Content-Type: application/json' -d "$BODY"

check 401 "неверный ключ -> 401" -X POST "$PROXY/v1/chat/completions" \
  -H "Authorization: Bearer wrong-key-0000000000000000" -H 'Content-Type: application/json' -d "$BODY"

check 403 "запрещённая модель -> 403" -X POST "$PROXY/v1/chat/completions" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"model":"o3-pro","messages":[{"role":"user","content":"hi"}]}'

check 400 "битый JSON -> 400" -X POST "$PROXY/v1/chat/completions" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d '{oops'

check 404 "чужой путь не проксируется -> 404" -X POST "$PROXY/v1/embeddings" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d "$BODY"

check 413 "тело 2 МиБ -> 413" -X POST "$PROXY/v1/chat/completions" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  --data-binary "@/tmp/smoke_big.json"

check 200 "обычный запрос -> 200" -X POST "$PROXY/v1/chat/completions" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d "$BODY"
echo "     ответ: $(head -c 200 /tmp/smoke_body)"

echo
echo "Стриминг (кусочки должны появляться с паузами, а не все сразу):"
curl -sN -X POST "$PROXY/v1/chat/completions" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"один два три"}]}' \
  | while IFS= read -r line; do
      [ -n "$line" ] && printf '  [%s] %s\n' "$(date +%H:%M:%S)" "$line"
    done

echo
echo "Лимит запросов (RATE_LIMIT_PER_MIN): подряд до первого 429"
for i in $(seq 1 12); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$PROXY/v1/chat/completions" \
    -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d "$BODY")
  printf '  запрос %2d -> %s\n' "$i" "$code"
  [ "$code" = "429" ] && { echo "  ✅ лимит сработал"; break; }
done
