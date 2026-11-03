# esaalat (Python)

**Server-side [Esaalat](https://esaalat.com) client.** It does the three things
a merchant backend always writes by hand — the 1-hour token, the idempotency
key, and the webhook HMAC — so an integration is three calls instead of forty
lines.

- **Locked checkout sessions** — create the session on your server, give the
  browser only the token.
- **Payment intents** — create one server-side for platform orders, attach the
  buyer's reference, read status.
- **Signed webhooks** — verify `X-Esaalat-Signature` over the raw body, with a
  replay window.
- **No dependencies** — standard library only (`urllib`, `hmac`, `json`).

## Install

```bash
pip install esaalat
```

## Quick start

```python
from esaalat import EsaalatClient

# Reads ESAALAT_CLIENT_ID, ESAALAT_CLIENT_SECRET and ESAALAT_WEBHOOK_SECRET.
esaalat = EsaalatClient.from_env()

# 1. Your server decides the amount; the browser gets only the token.
session = esaalat.create_session(order_id="order-123", amount=5000)
session["session_token"]  # → checkout.open({ sessionToken }) in the browser
session["portal_url"]     # → or send the buyer straight to this page

# 2. Fulfil on the signed webhook, never on the buyer's page.
@app.post("/esaalat/webhooks")
def webhook():
    try:
        event = esaalat.verify_webhook(
            request.data,                      # the RAW body
            request.headers["X-Esaalat-Signature"],
        )
    except EsaalatWebhookError:
        return "", 400

    if event["event"] == "payment.verified":
        mark_order_paid(event["order_id"])     # idempotent on intent_id
    return "", 200
```

Also available: `create_intent(wallet=..., amount=..., order_id=...)`,
`retrieve_intent(intent_id)`, `attach_reference(intent_id, reference)` and
`format_amount(value)`.

## What it handles for you

| | |
|---|---|
| **Token** | Issued once per client, cached, refreshed a minute before the JWT's own `exp`. |
| **Idempotency** | A UUID per create call, reused on every retry — a 429 or a timeout can never double-book an order. |
| **Retries** | `429`, `5xx` and network failures, honouring `Retry-After`. |
| **Errors** | `EsaalatError` with `code`, `status`, `detail`, `attr` and the API's per-field `errors`. |
| **Webhooks** | `hmac.compare_digest`, optional ±5 min window, `400`-shaped `EsaalatWebhookError`. |

## Configuration

| Argument | Environment | Default |
|---|---|---|
| `client_id` | `ESAALAT_CLIENT_ID` | — (required) |
| `client_secret` | `ESAALAT_CLIENT_SECRET` | — (required) |
| `webhook_secret` | `ESAALAT_WEBHOOK_SECRET` | — (needed by `verify_webhook`) |
| `base_url` | `ESAALAT_BASE_URL` | `https://api.esaalat.com/api/v1` |
| `timeout` | — | `20` seconds |
| `max_retries` | — | `2` |

Every endpoint takes a `secret=` override in `verify_webhook`, because each
webhook endpoint on the dashboard has its own signing secret.

## Notes

- The client secret is a **server** secret. Never call this from a browser or
  ship it in a mobile app; the browser only ever needs the session token.
- Amounts are whole Yemeni riyals. `format_amount(5000.5)` refuses before the
  request leaves your process.
- The webhook body must be the **raw** bytes: `json.dumps(request.get_json())`
  will not match the signature.

## Development

```bash
python -m unittest discover -s tests -t .
```

## License

MIT © Esaalat
