"""Outbound URL guard for the stdlib HTTP clients.

``urllib.request.urlopen`` also opens ``file://`` and custom schemes (bandit
B310). Every kernel client that calls it accepts only http(s) URLs with a host.
"""

from __future__ import annotations

from urllib.parse import urlsplit


def require_http_url(url: object, what: str = "endpoint URL") -> str:
    """Return ``url`` if it is an http:// or https:// URL with a host, else raise ``ValueError``."""
    parts = urlsplit(url) if isinstance(url, str) else None
    if parts is None or parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"{what} must be an http:// or https:// URL")
    return url  # type: ignore[return-value]
