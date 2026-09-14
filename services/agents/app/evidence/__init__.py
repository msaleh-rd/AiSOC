"""Platform evidence collection — query AiSOC's own alert store for context."""

from .platform_store import close_pool, collect_related_alerts

__all__ = ["close_pool", "collect_related_alerts"]
