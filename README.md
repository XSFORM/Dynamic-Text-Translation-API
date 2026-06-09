# Dynamic Text Translation API

A fast, self-hosted REST API for dynamic text translation with support for multiple language backends and real-time processing.

---

## Features

- RESTful API with JSON request/response format for easy integration.
- Pluggable translation backends: swap engines without changing your code.
- Built-in rate limiting and request queuing for high-throughput workloads.
- Domain-aware routing: route translation requests to specialized models per domain (legal, medical, technical).
- Async processing pipeline built on `asyncio` for low-latency responses.
- Admin dashboard via Telegram bot for monitoring, configuration, and usage stats.
- Encrypted backup/restore for seamless migration between servers.

---

## Installation

```bash
pip install dynamic-text-translation-api
```

Requires Python 3.8+.

---

## Quick start

### Python client

```python
from dtta import TranslationClient

client = TranslationClient(base_url="http://localhost:8080")
result = client.translate("Hello, world!", source="en", target="ru")
print(result.text)  # "Привет, мир!"
```

Batch translation:

```python
texts = ["Good morning", "Thank you", "See you later"]
results = client.translate_batch(texts, source="en", target="de")
for r in results:
    print(r.text)
```

### cURL

```bash
# Single translation
curl -X POST http://localhost:8080/api/v1/translate \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello", "source": "en", "target": "fr"}'

# Health check
curl http://localhost:8080/api/v1/health
```

---

## Supported languages

All languages provided by the configured backend. With the default engine:

| Code | Language   | Code | Language   |
|------|-----------|------|-----------|
| `en` | English    | `de` | German     |
| `ru` | Russian    | `fr` | French     |
| `es` | Spanish    | `zh` | Chinese    |
| `ja` | Japanese   | `ar` | Arabic     |
| `pt` | Portuguese | `ko` | Korean     |
| `it` | Italian    | `tr` | Turkish    |

---

## Configuration

Server configuration via environment variables or `/etc/dtta.conf`:

```ini
[server]
host = 0.0.0.0
port = 8080
workers = 4

[translation]
backend = default
cache_ttl = 3600
max_text_length = 5000

[auth]
api_key = your-api-key-here
rate_limit = 100/min
```

Environment variables take precedence:

```bash
export DTTA_BACKEND=deepl
export DTTA_API_KEY=your-key
export DTTA_RATE_LIMIT=200
```

---

## Backends

| Backend    | Description                        | Extra dependency           |
|------------|------------------------------------|----------------------------|
| `default`  | Free, no API key required          | —                          |
| `deepl`    | DeepL API (high quality)           | `deepl`                    |
| `google`   | Google Cloud Translation           | `google-cloud-translate`   |
| `azure`    | Azure Cognitive Services           | `azure-ai-translation`     |

Install backend dependencies:

```bash
pip install dynamic-text-translation-api[deepl]
```

---

## API Reference

| Method | Endpoint                | Description              |
|--------|------------------------|--------------------------|
| POST   | `/api/v1/translate`     | Translate text           |
| POST   | `/api/v1/batch`         | Batch translate          |
| GET    | `/api/v1/languages`     | List supported languages |
| GET    | `/api/v1/health`        | Service health check     |
| GET    | `/api/v1/stats`         | Usage statistics         |

---

## License

MIT License. See [LICENSE](LICENSE) for details.
