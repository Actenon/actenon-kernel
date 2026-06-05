from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Sequence
from urllib.error import URLError
from urllib.parse import SplitResult, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from actenon.core.json import loads_no_duplicate_keys
from actenon.models.contracts import PartyRef, SignatureSpec, format_timestamp, parse_timestamp

from .base import b64url_decode


WELL_KNOWN_KEYS_PATH = "/.well-known/actenon/keys.json"
DEFAULT_WELL_KNOWN_CACHE_MAX_AGE_SECONDS = 300
ALLOWED_DISCOVERY_KEY_STATUSES = ("active", "retired", "suspended", "revoked", "hard_revoked")
ALLOWED_DISCOVERY_KEY_USES = ("verify", "proof_issuance", "outcome_attestation")
PROOF_ISSUANCE_USE = "proof_issuance"
OUTCOME_ATTESTATION_USE = "outcome_attestation"
LEGACY_VERIFY_USE = "verify"
_BASE64URL_UNPADDED_RE = re.compile(r"^[A-Za-z0-9_-]+$")
MIN_RS256_MODULUS_BITS = 2048
EXPECTED_RS256_PUBLIC_EXPONENT = 65537
_BLOCKED_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "metadata",
        "metadata.google.internal",
    }
)


class WellKnownKeyResolverError(Exception):
    """Base class for well-known key-discovery failures."""


class KeyDiscoveryFetchError(WellKnownKeyResolverError):
    """Raised when the discovery document cannot be fetched."""


class KeyDiscoveryFormatError(WellKnownKeyResolverError):
    """Raised when the discovery document shape is invalid."""


class KeyNotFoundError(WellKnownKeyResolverError):
    """Raised when no matching key is published for the requested key id."""


class IssuerMismatchError(WellKnownKeyResolverError):
    """Raised when the discovery document issuer does not match the artifact issuer."""


class RevokedKeyError(WellKnownKeyResolverError):
    """Raised when the resolved key is revoked for the artifact issuance time."""


class KeyPurposeMismatchError(WellKnownKeyResolverError):
    """Raised when a discovery key is not authorized for the required use."""


class ExpiredKeyError(WellKnownKeyResolverError):
    """Raised when the resolved key is expired for the artifact issuance time."""


class KeyNotYetValidError(WellKnownKeyResolverError):
    """Raised when the resolved key is not yet valid for the artifact issuance time."""


class UnsupportedVerificationAlgorithmError(WellKnownKeyResolverError):
    """Raised when the local runtime cannot verify the discovered key algorithm."""


@dataclass(frozen=True)
class DiscoveredVerificationKey:
    key_id: str
    algorithm: str
    use: tuple[str, ...]
    status: str
    public_key_jwk: dict[str, Any]
    not_before: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    hard_revoked_at: datetime | None = None
    replaced_by: str | None = None
    revocation_reason: dict[str, Any] | str | None = None


@dataclass(frozen=True)
class KeyDiscoveryDocument:
    issuer: PartyRef
    origin: str
    published_at: datetime
    keys: tuple[DiscoveredVerificationKey, ...]
    cache_max_age_seconds: int | None = None


@dataclass(frozen=True)
class ResolvedVerificationKey:
    issuer: PartyRef
    origin: str
    published_at: datetime
    key: DiscoveredVerificationKey


FetchHeaders = Mapping[str, str]
WellKnownDocumentFetcher = Callable[[str, float], tuple[FetchHeaders, bytes]]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_origin(origin: str) -> str:
    parts = urlsplit(origin)
    if parts.scheme != "https":
        raise ValueError("issuer_origin must use https")
    if not parts.netloc or not parts.hostname:
        raise ValueError("issuer_origin must include a host")
    if parts.username is not None or parts.password is not None:
        raise ValueError("issuer_origin must not include userinfo")
    try:
        _assert_host_is_not_blocked_ip_literal(parts.hostname, field_name="issuer_origin")
        parts.port
    except (KeyDiscoveryFetchError, ValueError) as exc:
        raise ValueError(str(exc)) from exc
    if parts.query or parts.fragment:
        raise ValueError("issuer_origin must not include query or fragment components")
    if parts.path not in ("", "/"):
        raise ValueError("issuer_origin must be an origin, not a full URL path")
    return f"{parts.scheme}://{parts.netloc.lower()}"


def _default_fetch_document(url: str, timeout_seconds: float) -> tuple[FetchHeaders, bytes]:
    expected_origin = _origin_from_url(url, field_name="well-known discovery URL")
    _validate_well_known_fetch_url(url, expected_origin=expected_origin, resolve_host=True)
    request = Request(url, headers={"Accept": "application/json"})
    try:
        opener = build_opener(_NoRedirectHandler)
        with opener.open(request, timeout=timeout_seconds) as response:
            final_url = response.geturl()
            _validate_well_known_fetch_url(final_url, expected_origin=expected_origin, resolve_host=False)
            body = response.read()
            headers = {key.lower(): value for key, value in response.headers.items()}
            return headers, body
    except URLError as exc:
        raise KeyDiscoveryFetchError(f"could not fetch well-known key document from {url}: {exc}") from exc


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _port_or_raise(parts: SplitResult, *, field_name: str) -> int | None:
    try:
        return parts.port
    except ValueError as exc:
        raise KeyDiscoveryFetchError(f"{field_name} has an invalid port") from exc


def _origin_from_url(url: str, *, field_name: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise KeyDiscoveryFetchError(f"{field_name} must use https")
    if not parts.netloc or not parts.hostname:
        raise KeyDiscoveryFetchError(f"{field_name} must include a host")
    if parts.username is not None or parts.password is not None:
        raise KeyDiscoveryFetchError(f"{field_name} must not include userinfo")
    _port_or_raise(parts, field_name=field_name)
    return f"{parts.scheme}://{parts.netloc.lower()}"


def _is_blocked_ip_address(ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(
        (
            ip_address.is_loopback,
            ip_address.is_link_local,
            ip_address.is_private,
            ip_address.is_multicast,
            ip_address.is_unspecified,
            ip_address.is_reserved,
        )
    )


def _assert_public_ip_address(ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address, *, field_name: str) -> None:
    if _is_blocked_ip_address(ip_address):
        raise KeyDiscoveryFetchError(f"{field_name} resolves to a non-public IP address")


def _assert_host_is_not_blocked_ip_literal(host: str, *, field_name: str) -> None:
    normalized_host = host.strip("[]").lower()
    if normalized_host in _BLOCKED_METADATA_HOSTS:
        raise KeyDiscoveryFetchError(f"{field_name} uses a blocked metadata host")
    try:
        parsed = ipaddress.ip_address(normalized_host)
    except ValueError:
        return
    _assert_public_ip_address(parsed, field_name=field_name)


def _assert_resolved_host_is_public(host: str, *, field_name: str) -> None:
    normalized_host = host.strip("[]").lower()
    if normalized_host in _BLOCKED_METADATA_HOSTS:
        raise KeyDiscoveryFetchError(f"{field_name} uses a blocked metadata host")
    try:
        resolved = socket.getaddrinfo(normalized_host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise KeyDiscoveryFetchError(f"could not resolve {field_name} host {host!r}: {exc}") from exc
    for family, _socktype, _proto, _canonname, sockaddr in resolved:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = sockaddr[0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise KeyDiscoveryFetchError(f"{field_name} resolved to an invalid IP address {address!r}") from exc
        _assert_public_ip_address(parsed, field_name=field_name)


def _validate_well_known_fetch_url(
    url: str,
    *,
    expected_origin: str,
    resolve_host: bool,
) -> None:
    parts = urlsplit(url)
    origin = _origin_from_url(url, field_name="well-known discovery URL")
    if origin != expected_origin:
        raise KeyDiscoveryFetchError(
            f"well-known discovery URL origin {origin!r} does not match expected issuer origin {expected_origin!r}"
        )
    if parts.path != WELL_KNOWN_KEYS_PATH:
        raise KeyDiscoveryFetchError(
            f"well-known discovery URL path must be {WELL_KNOWN_KEYS_PATH!r}"
        )
    if parts.query or parts.fragment:
        raise KeyDiscoveryFetchError("well-known discovery URL must not include query or fragment components")
    if parts.hostname is None:
        raise KeyDiscoveryFetchError("well-known discovery URL must include a host")
    _assert_host_is_not_blocked_ip_literal(parts.hostname, field_name="well-known discovery URL")
    if resolve_host:
        _assert_resolved_host_is_public(parts.hostname, field_name="well-known discovery URL")


def _parse_positive_int(raw: Any, field_name: str) -> int:
    if not isinstance(raw, int) or raw <= 0:
        raise KeyDiscoveryFormatError(f"{field_name} must be a positive integer")
    return raw


def _parse_cache_control_max_age(raw: str | None) -> int | None:
    if raw is None:
        return None
    for part in raw.split(","):
        part = part.strip().lower()
        if part.startswith("max-age="):
            value = part.split("=", 1)[1].strip()
            try:
                parsed = int(value)
            except ValueError:
                return None
            return parsed if parsed > 0 else None
    return None


def _normalize_public_key_jwk(*, public_key_jwk: Mapping[str, Any], key_id: str, algorithm: str) -> dict[str, Any]:
    if not isinstance(public_key_jwk, Mapping):
        raise ValueError("public_key_jwk must be a JSON object")
    jwk = dict(public_key_jwk)
    kid = jwk.get("kid")
    if kid is not None and kid != key_id:
        raise ValueError(f"public_key_jwk.kid {kid!r} does not match key_id {key_id!r}")
    alg = jwk.get("alg")
    if alg is not None and alg != algorithm:
        raise ValueError(f"public_key_jwk.alg {alg!r} does not match algorithm {algorithm!r}")
    use = jwk.get("use")
    if use is not None and use != "sig":
        raise ValueError("public_key_jwk.use must be 'sig' when provided")
    jwk.setdefault("kid", key_id)
    jwk.setdefault("alg", algorithm)
    jwk.setdefault("use", "sig")
    return jwk


def _normalize_key_uses(raw: Any) -> tuple[str, ...]:
    if isinstance(raw, str):
        uses = (raw,)
    elif isinstance(raw, Sequence) and not isinstance(raw, (bytes, bytearray, str)):
        uses = tuple(raw)
    else:
        raise KeyDiscoveryFormatError("keys[].use must be a non-empty string or array of strings")
    if not uses:
        raise KeyDiscoveryFormatError("keys[].use must not be empty")
    normalized: list[str] = []
    for use in uses:
        if not isinstance(use, str) or not use:
            raise KeyDiscoveryFormatError("keys[].use entries must be non-empty strings")
        if use not in ALLOWED_DISCOVERY_KEY_USES:
            raise KeyDiscoveryFormatError(
                f"keys[].use {use!r} is not supported; expected one of {', '.join(ALLOWED_DISCOVERY_KEY_USES)}"
            )
        if use not in normalized:
            normalized.append(use)
    return tuple(normalized)


def _serialize_key_use(use: str | Sequence[str]) -> str | list[str]:
    normalized = _normalize_key_uses(use)
    if len(normalized) == 1:
        return normalized[0]
    return list(normalized)


def build_key_discovery_document(
    *,
    issuer: PartyRef,
    origin: str,
    key_id: str,
    algorithm: str,
    public_key_jwk: Mapping[str, Any],
    published_at: datetime,
    status: str = "active",
    use: str | Sequence[str] = LEGACY_VERIFY_USE,
    cache_max_age_seconds: int = DEFAULT_WELL_KNOWN_CACHE_MAX_AGE_SECONDS,
    not_before: datetime | None = None,
    expires_at: datetime | None = None,
    revoked_at: datetime | None = None,
    hard_revoked_at: datetime | None = None,
    replaced_by: str | None = None,
    revocation_reason: Mapping[str, Any] | str | None = None,
) -> dict[str, Any]:
    if status not in ALLOWED_DISCOVERY_KEY_STATUSES:
        raise ValueError(f"status must be one of {', '.join(ALLOWED_DISCOVERY_KEY_STATUSES)}")
    if cache_max_age_seconds <= 0:
        raise ValueError("cache_max_age_seconds must be positive")
    normalized_origin = _normalize_origin(origin)
    key_payload: dict[str, Any] = {
        "key_id": key_id,
        "algorithm": algorithm,
        "use": _serialize_key_use(use),
        "status": status,
        "public_key_jwk": _normalize_public_key_jwk(
            public_key_jwk=public_key_jwk,
            key_id=key_id,
            algorithm=algorithm,
        ),
    }
    if not_before is not None:
        key_payload["not_before"] = format_timestamp(not_before)
    if expires_at is not None:
        key_payload["expires_at"] = format_timestamp(expires_at)
    if revoked_at is not None:
        key_payload["revoked_at"] = format_timestamp(revoked_at)
    if hard_revoked_at is not None:
        key_payload["hard_revoked_at"] = format_timestamp(hard_revoked_at)
    if replaced_by is not None:
        key_payload["replaced_by"] = replaced_by
    if revocation_reason is not None:
        key_payload["revocation_reason"] = revocation_reason

    return {
        "contract": {"name": "key_discovery", "version": "v1"},
        "issuer": issuer.to_dict(),
        "origin": normalized_origin,
        "published_at": format_timestamp(published_at),
        "cache": {"max_age_seconds": cache_max_age_seconds},
        "keys": [key_payload],
    }


def _parse_key_descriptor(raw: Any) -> DiscoveredVerificationKey:
    if not isinstance(raw, Mapping):
        raise KeyDiscoveryFormatError("keys[] must be an object")
    key_id = raw.get("key_id") or raw.get("kid")
    if not isinstance(key_id, str) or not key_id:
        raise KeyDiscoveryFormatError("keys[].key_id must be a non-empty string")
    if raw.get("key_id") is not None and raw.get("kid") is not None and raw["key_id"] != raw["kid"]:
        raise KeyDiscoveryFormatError("keys[].kid must match keys[].key_id when both are present")
    required_fields = ("algorithm", "use", "status", "public_key_jwk")
    for field_name in required_fields:
        value = raw.get(field_name)
        if field_name == "public_key_jwk":
            if not isinstance(value, Mapping):
                raise KeyDiscoveryFormatError("keys[].public_key_jwk must be an object")
            continue
        if field_name == "use":
            _normalize_key_uses(value)
            continue
        if not isinstance(value, str) or not value:
            raise KeyDiscoveryFormatError(f"keys[].{field_name} must be a non-empty string")
    return DiscoveredVerificationKey(
        key_id=key_id,
        algorithm=raw["algorithm"],
        use=_normalize_key_uses(raw["use"]),
        status=raw["status"],
        public_key_jwk=dict(raw["public_key_jwk"]),
        not_before=parse_timestamp(raw["not_before"], "keys[].not_before") if raw.get("not_before") else None,
        expires_at=parse_timestamp(raw["expires_at"], "keys[].expires_at") if raw.get("expires_at") else None,
        revoked_at=parse_timestamp(raw["revoked_at"], "keys[].revoked_at") if raw.get("revoked_at") else None,
        hard_revoked_at=parse_timestamp(raw["hard_revoked_at"], "keys[].hard_revoked_at") if raw.get("hard_revoked_at") else None,
        replaced_by=raw.get("replaced_by"),
        revocation_reason=raw.get("revocation_reason"),
    )


def _parse_discovery_document(*, body: bytes, expected_origin: str, fetched_url: str) -> KeyDiscoveryDocument:
    try:
        payload = loads_no_duplicate_keys(body)
    except ValueError as exc:
        raise KeyDiscoveryFormatError(
            "well-known key document must be valid JSON without duplicate object keys and within size/depth limits"
        ) from exc
    if not isinstance(payload, Mapping):
        raise KeyDiscoveryFormatError("well-known key document must be a JSON object")

    contract = payload.get("contract")
    if not isinstance(contract, Mapping):
        raise KeyDiscoveryFormatError("contract must be an object")
    if contract.get("name") != "key_discovery" or contract.get("version") != "v1":
        raise KeyDiscoveryFormatError("contract must declare key_discovery v1")

    origin = payload.get("origin")
    if not isinstance(origin, str) or not origin:
        raise KeyDiscoveryFormatError("origin must be a non-empty string")
    normalized_origin = _normalize_origin(origin)
    if normalized_origin != expected_origin:
        raise KeyDiscoveryFormatError(
            f"well-known key document origin {normalized_origin!r} does not match fetched origin {expected_origin!r}"
        )
    fetched_origin = f"{urlsplit(fetched_url).scheme}://{urlsplit(fetched_url).netloc}"
    if normalized_origin != fetched_origin:
        raise KeyDiscoveryFormatError(
            f"well-known key document origin {normalized_origin!r} does not match fetched URL origin {fetched_origin!r}"
        )

    issuer = PartyRef.from_dict(payload.get("issuer"), "issuer")
    published_at = parse_timestamp(payload.get("published_at"), "published_at")

    raw_cache = payload.get("cache", {})
    if raw_cache is None:
        raw_cache = {}
    if not isinstance(raw_cache, Mapping):
        raise KeyDiscoveryFormatError("cache must be an object when present")
    cache_max_age_seconds = (
        _parse_positive_int(raw_cache.get("max_age_seconds"), "cache.max_age_seconds")
        if raw_cache.get("max_age_seconds") is not None
        else None
    )

    raw_keys = payload.get("keys")
    if not isinstance(raw_keys, list) or not raw_keys:
        raise KeyDiscoveryFormatError("keys must be a non-empty array")
    keys = tuple(_parse_key_descriptor(item) for item in raw_keys)
    seen_key_ids: set[str] = set()
    for key in keys:
        if key.key_id in seen_key_ids:
            raise KeyDiscoveryFormatError(f"duplicate key_id {key.key_id!r} in key-discovery document")
        seen_key_ids.add(key.key_id)

    return KeyDiscoveryDocument(
        issuer=issuer,
        origin=normalized_origin,
        published_at=published_at,
        keys=keys,
        cache_max_age_seconds=cache_max_age_seconds,
    )


@dataclass(frozen=True)
class _CachedDiscoveryDocument:
    document: KeyDiscoveryDocument
    expires_at: datetime


@dataclass
class WellKnownKeyResolver:
    """Resolve issuer verification keys from a well-known discovery document.

    The zero-dependency path handles HTTPS fetch, JSON parsing, key selection,
    status checks, and caching. Actual asymmetric signature verification is
    available only when an optional crypto backend is importable.
    """

    issuer_origin: str
    timeout_seconds: float = 5.0
    default_cache_max_age_seconds: int = DEFAULT_WELL_KNOWN_CACHE_MAX_AGE_SECONDS
    fetch_document: WellKnownDocumentFetcher = _default_fetch_document
    now_provider: Callable[[], datetime] = _utc_now
    _cache: _CachedDiscoveryDocument | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.issuer_origin = _normalize_origin(self.issuer_origin)
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.default_cache_max_age_seconds <= 0:
            raise ValueError("default_cache_max_age_seconds must be positive")

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer_origin}{WELL_KNOWN_KEYS_PATH}"

    def resolve_key(
        self,
        *,
        key_id: str,
        algorithm: str,
        issued_at: datetime,
        issuer: PartyRef | None = None,
        required_use: str | None = None,
        external_anchor_verified: bool = False,
        external_anchor_time: datetime | None = None,
        bypass_cache: bool = False,
    ) -> ResolvedVerificationKey:
        document = self._get_document(bypass_cache=bypass_cache)
        try:
            return self._select_key(
                document=document,
                key_id=key_id,
                algorithm=algorithm,
                issued_at=issued_at,
                issuer=issuer,
                required_use=required_use,
                external_anchor_verified=external_anchor_verified,
                external_anchor_time=external_anchor_time,
            )
        except KeyNotFoundError:
            if bypass_cache or self._cache is None:
                raise
        refreshed = self._get_document(bypass_cache=True)
        return self._select_key(
            document=refreshed,
            key_id=key_id,
            algorithm=algorithm,
            issued_at=issued_at,
            issuer=issuer,
            required_use=required_use,
            external_anchor_verified=external_anchor_verified,
            external_anchor_time=external_anchor_time,
        )

    def _get_document(self, *, bypass_cache: bool) -> KeyDiscoveryDocument:
        now = self.now_provider()
        if not bypass_cache and self._cache is not None and now < self._cache.expires_at:
            return self._cache.document

        discovery_url = self.discovery_url
        _validate_well_known_fetch_url(
            discovery_url,
            expected_origin=self.issuer_origin,
            resolve_host=self.fetch_document is _default_fetch_document,
        )
        headers, body = self.fetch_document(discovery_url, self.timeout_seconds)
        normalized_headers = {key.lower(): value for key, value in headers.items()}
        document = _parse_discovery_document(
            body=body,
            expected_origin=self.issuer_origin,
            fetched_url=discovery_url,
        )
        cache_control_max_age = _parse_cache_control_max_age(normalized_headers.get("cache-control"))
        advisory_max_age = document.cache_max_age_seconds
        candidates = [value for value in (cache_control_max_age, advisory_max_age) if value is not None]
        max_age_seconds = min(candidates) if candidates else self.default_cache_max_age_seconds
        self._cache = _CachedDiscoveryDocument(document=document, expires_at=now + timedelta(seconds=max_age_seconds))
        return document

    def _select_key(
        self,
        *,
        document: KeyDiscoveryDocument,
        key_id: str,
        algorithm: str,
        issued_at: datetime,
        issuer: PartyRef | None,
        required_use: str | None,
        external_anchor_verified: bool,
        external_anchor_time: datetime | None,
    ) -> ResolvedVerificationKey:
        if issuer is not None and (document.issuer.type != issuer.type or document.issuer.id != issuer.id):
            raise IssuerMismatchError(
                f"discovery document issuer {document.issuer.type}:{document.issuer.id} does not match artifact issuer {issuer.type}:{issuer.id}"
            )

        matches = [item for item in document.keys if item.key_id == key_id]
        if not matches:
            raise KeyNotFoundError(f"no discovery key matched key_id {key_id!r}")
        if len(matches) > 1:
            raise KeyDiscoveryFormatError(f"multiple discovery keys matched key_id {key_id!r}")
        key = matches[0]
        if key.algorithm != algorithm:
            raise KeyNotFoundError(
                f"discovery key {key_id!r} advertises algorithm {key.algorithm!r}, not {algorithm!r}"
            )
        self._assert_key_usable(
            key=key,
            issued_at=issued_at,
            required_use=required_use,
            external_anchor_verified=external_anchor_verified,
            external_anchor_time=external_anchor_time,
        )
        return ResolvedVerificationKey(
            issuer=document.issuer,
            origin=document.origin,
            published_at=document.published_at,
            key=key,
        )

    def _assert_key_usable(
        self,
        *,
        key: DiscoveredVerificationKey,
        issued_at: datetime,
        required_use: str | None,
        external_anchor_verified: bool,
        external_anchor_time: datetime | None,
    ) -> None:
        if key.status not in ALLOWED_DISCOVERY_KEY_STATUSES:
            raise KeyDiscoveryFormatError(f"discovery key {key.key_id!r} has unsupported status {key.status!r}")
        if required_use is not None:
            if required_use not in ALLOWED_DISCOVERY_KEY_USES or required_use == LEGACY_VERIFY_USE:
                raise KeyDiscoveryFormatError(f"required_use {required_use!r} is not a supported purpose")
            if required_use not in key.use:
                raise KeyPurposeMismatchError(
                    f"discovery key {key.key_id!r} is not authorized for required use {required_use!r}"
                )
        elif not any(use in ALLOWED_DISCOVERY_KEY_USES for use in key.use):
            raise KeyDiscoveryFormatError(f"discovery key {key.key_id!r} has no supported use")
        if key.not_before is not None and issued_at < key.not_before:
            raise KeyNotYetValidError(f"discovery key {key.key_id!r} is not yet valid for the artifact issuance time")
        if key.expires_at is not None and issued_at >= key.expires_at:
            raise ExpiredKeyError(f"discovery key {key.key_id!r} is expired for the artifact issuance time")
        if key.status == "suspended":
            raise RevokedKeyError(
                f"discovery key {key.key_id!r} is suspended; this pass has no timestamped suspension boundary for historical verification"
            )
        if key.status == "hard_revoked" or key.hard_revoked_at is not None:
            if (
                not external_anchor_verified
                or external_anchor_time is None
                or key.hard_revoked_at is None
                or external_anchor_time >= key.hard_revoked_at
            ):
                raise RevokedKeyError(
                    f"discovery key {key.key_id!r} is hard-revoked and requires an independently verified pre-revocation external anchor"
                )
        if key.status == "revoked" and key.revoked_at is None:
            raise RevokedKeyError(f"discovery key {key.key_id!r} is revoked without an issue-time boundary")
        if key.revoked_at is not None and issued_at >= key.revoked_at:
            raise RevokedKeyError(f"discovery key {key.key_id!r} was revoked before or at the artifact issuance time")


def _load_optional_crypto_backend() -> dict[str, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
    except Exception as exc:
        raise UnsupportedVerificationAlgorithmError(
            "asymmetric well-known key verification requires the optional 'cryptography' package in the current Python path"
        ) from exc
    return {
        "InvalidSignature": InvalidSignature,
        "ed25519": ed25519,
        "padding": padding,
        "rsa": rsa,
        "hashes": hashes,
    }


def _decode_unpadded_base64url_wire(raw: str, field_name: str) -> bytes:
    if not isinstance(raw, str) or not raw:
        raise KeyDiscoveryFormatError(f"{field_name} must be a non-empty base64url string")
    if "=" in raw:
        raise KeyDiscoveryFormatError(f"{field_name} must be base64url without padding")
    if _BASE64URL_UNPADDED_RE.fullmatch(raw) is None:
        raise KeyDiscoveryFormatError(f"{field_name} contains characters outside unpadded base64url")
    try:
        return b64url_decode(raw)
    except Exception as exc:
        raise KeyDiscoveryFormatError(f"{field_name} could not be decoded as base64url") from exc


def _verify_signature_with_resolved_key(*, payload: bytes, signature: SignatureSpec, resolved_key: ResolvedVerificationKey) -> bool:
    if signature.encoding != "base64url":
        return False
    jwk = resolved_key.key.public_key_jwk
    if not isinstance(jwk, Mapping):
        raise KeyDiscoveryFormatError("discovery key public_key_jwk must be an object")
    if jwk.get("kid") not in (None, resolved_key.key.key_id):
        raise KeyDiscoveryFormatError("public_key_jwk.kid does not match the discovery key_id")
    if jwk.get("alg") not in (None, signature.algorithm):
        raise KeyDiscoveryFormatError("public_key_jwk.alg does not match the signature algorithm")

    crypto = _load_optional_crypto_backend()
    raw_signature = _decode_unpadded_base64url_wire(signature.value, "signature.value")
    invalid_signature = crypto["InvalidSignature"]

    try:
        if signature.algorithm == "EdDSA":
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                raise KeyDiscoveryFormatError("EdDSA discovery keys must publish an Ed25519 OKP JWK")
            public_key_bytes = _decode_unpadded_base64url_wire(jwk["x"], "public_key_jwk.x")
            if len(public_key_bytes) != 32:
                raise KeyDiscoveryFormatError("EdDSA discovery keys must publish a raw 32-byte Ed25519 public key")
            if len(raw_signature) != 64:
                return False
            public_key = crypto["ed25519"].Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(raw_signature, payload)
            return True

        if signature.algorithm == "RS256":
            if jwk.get("kty") != "RSA":
                raise KeyDiscoveryFormatError("RS256 discovery keys must publish an RSA JWK")
            modulus = int.from_bytes(_decode_unpadded_base64url_wire(jwk["n"], "public_key_jwk.n"), "big")
            exponent = int.from_bytes(_decode_unpadded_base64url_wire(jwk["e"], "public_key_jwk.e"), "big")
            if modulus.bit_length() < MIN_RS256_MODULUS_BITS:
                raise KeyDiscoveryFormatError(
                    f"RS256 discovery keys must use RSA modulus size >= {MIN_RS256_MODULUS_BITS} bits"
                )
            if exponent != EXPECTED_RS256_PUBLIC_EXPONENT:
                raise KeyDiscoveryFormatError(
                    f"RS256 discovery keys must use public exponent {EXPECTED_RS256_PUBLIC_EXPONENT}"
                )
            try:
                public_key = crypto["rsa"].RSAPublicNumbers(exponent, modulus).public_key()
            except ValueError as exc:
                raise KeyDiscoveryFormatError("RS256 discovery key has invalid RSA public numbers") from exc
            public_key.verify(
                raw_signature,
                payload,
                crypto["padding"].PKCS1v15(),
                crypto["hashes"].SHA256(),
            )
            return True
    except KeyError as exc:
        raise KeyDiscoveryFormatError(f"public_key_jwk is missing required field {exc.args[0]!r}") from exc
    except invalid_signature:
        return False

    raise UnsupportedVerificationAlgorithmError(
        f"well-known verification supports RS256 and EdDSA only when the optional crypto backend is available; got {signature.algorithm!r}"
    )


@dataclass
class WellKnownKeySignatureVerifier:
    """Signature verifier that resolves verification keys from a well-known origin.

    This verifier is meant for deployments that already know the issuer origin
    but do not want manual bilateral distribution of every verification key.
    """

    resolver: WellKnownKeyResolver
    algorithm: str = "well-known-dynamic"
    key_id: str = "well-known-dynamic"
    required_use: str = PROOF_ISSUANCE_USE
    external_anchor_verified: bool = False
    external_anchor_time: datetime | None = None

    def verify(self, payload: bytes, signature: SignatureSpec) -> bool:
        # Time-bounded key validity needs artifact metadata, so the plain
        # SignatureVerifier hook is intentionally fail-closed here.
        return False

    def verify_with_metadata(
        self,
        payload: bytes,
        signature: SignatureSpec,
        *,
        issuer: PartyRef | None = None,
        issued_at: datetime | None = None,
        external_anchor_verified: bool | None = None,
        external_anchor_time: datetime | None = None,
    ) -> bool:
        if issued_at is None:
            return False
        resolved_external_anchor_verified = (
            self.external_anchor_verified
            if external_anchor_verified is None
            else external_anchor_verified
        )
        resolved_external_anchor_time = (
            self.external_anchor_time
            if external_anchor_time is None
            else external_anchor_time
        )
        try:
            resolved_key = self.resolver.resolve_key(
                key_id=signature.key_id,
                algorithm=signature.algorithm,
                issued_at=issued_at,
                issuer=issuer,
                required_use=self.required_use,
                external_anchor_verified=resolved_external_anchor_verified,
                external_anchor_time=resolved_external_anchor_time,
            )
            return _verify_signature_with_resolved_key(
                payload=payload,
                signature=signature,
                resolved_key=resolved_key,
            )
        except WellKnownKeyResolverError:
            return False
