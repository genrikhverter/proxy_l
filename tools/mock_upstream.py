#!/usr/bin/env python3
"""Игрушечный LLM-провайдер для локальной проверки прокси (без затрат на API).

Запуск:  python3 tools/mock_upstream.py
Слушает http://127.0.0.1:9001/v1/chat/completions, требует ключ "test-upstream-key".
Умеет и обычный ответ, и SSE-стрим (stream: true).
"""
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM_KEY = "test-upstream-key"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # тише в консоли
        print("[upstream] " + fmt % args)

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            return self.send_json(404, {"error": {"message": "unknown path"}})

        if self.headers.get("Authorization") != f"Bearer {UPSTREAM_KEY}":
            # Как у настоящего OpenAI: в тексте ошибки видно начало ключа.
            return self.send_json(401, {"error": {"message": "Incorrect API key provided: test-up***"}})

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        model = body.get("model", "?")
        prompt = body.get("messages", [{}])[-1].get("content", "")
        answer = f"Эхо от {model}: {prompt[:80]}"

        if body.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for word in answer.split():
                payload = {"choices": [{"delta": {"content": word + " "}}]}
                self.write_chunk(f"data: {json.dumps(payload, ensure_ascii=False)}\n\n")
                time.sleep(0.3)  # имитируем «думающую» модель
            self.write_chunk("data: [DONE]\n\n")
            self.write_chunk("")  # конец chunked-ответа
            return

        self.send_json(200, {
            "id": "chatcmpl-mock",
            "model": model,
            "choices": [{"message": {"role": "assistant", "content": answer}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
        })

    def write_chunk(self, text):
        data = text.encode()
        self.wfile.write(f"{len(data):X}\r\n".encode() + data + b"\r\n")
        self.wfile.flush()

    def send_json(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    print("мок-провайдер на http://127.0.0.1:9001 (ключ: test-upstream-key)")
    ThreadingHTTPServer(("127.0.0.1", 9001), Handler).serve_forever()
