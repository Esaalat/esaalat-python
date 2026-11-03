"""Server-side Esaalat client.

    from esaalat import EsaalatClient

    esaalat = EsaalatClient.from_env()
    session = esaalat.create_session(order_id="order-123", amount=5000)
    event = esaalat.verify_webhook(request.data, signature)
"""

from .client import DEFAULT_API_BASE, EsaalatClient, format_amount
from .errors import EsaalatError, EsaalatWebhookError

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_API_BASE",
    "EsaalatClient",
    "EsaalatError",
    "EsaalatWebhookError",
    "format_amount",
]
