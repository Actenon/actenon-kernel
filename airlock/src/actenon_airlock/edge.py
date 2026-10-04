"""The Airlock edge: the execution boundary for the agent's network actions.

The agent's HTTP(S) traffic is routed here (HTTP(S)_PROXY). For every request the edge:

1. parses the exact request (method, URL, headers, body) from the agent's TLS stream (local CA);
2. names the authority it needs with the same vocabulary static discovery uses;
3. refuses any credential placeholder bound for a host it does not belong to;
4. asks the decider (approved manifest -> Permit PDP -> kernel PCCB bound to method, URL and body digest);
5. rebuilds the action from the request bytes it is about to send and verifies the PCCB against them;
6. only then substitutes the real credential and forwards; otherwise it answers 403 itself, so a denied
   request never reaches the upstream and never carries a credential.

It also serves the in-process hook's decisions (file writes, process execution, direct connections) on
``/_airlock/decide``, authenticated with a per-run token.
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl
import threading
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from actenon_scan.authority import classify_http

from .ca import LocalCA
from .credentials import Vault
from .decision import ActionFacts, Authorization, Decider, body_digest

HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate", "te",
              "trailer", "transfer-encoding", "upgrade", "expect"}
MAX_BODY = 64 * 1024 * 1024
IDLE_TIMEOUT = 300


@dataclass
class RequestHead:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]

    def header(self, name: str) -> str | None:
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return None


async def _read_head(reader: asyncio.StreamReader) -> RequestHead | None:
    line = await asyncio.wait_for(reader.readline(), IDLE_TIMEOUT)
    while line in (b"\r\n", b"\n"):
        line = await asyncio.wait_for(reader.readline(), IDLE_TIMEOUT)
    if not line:
        return None
    parts = line.decode("latin-1").rstrip("\r\n").split(" ", 2)
    if len(parts) != 3:
        raise ValueError(f"malformed request line {line[:80]!r}")
    headers: list[tuple[str, str]] = []
    while True:
        h = await asyncio.wait_for(reader.readline(), IDLE_TIMEOUT)
        if h in (b"\r\n", b"\n", b""):
            break
        k, _, v = h.decode("latin-1").partition(":")
        headers.append((k.strip(), v.strip()))
        if len(headers) > 200:
            raise ValueError("too many headers")
    return RequestHead(parts[0].upper(), parts[1], parts[2], headers)


async def _read_body(reader: asyncio.StreamReader, head: RequestHead) -> bytes:
    te = (head.header("transfer-encoding") or "").lower()
    if "chunked" in te:
        out = bytearray()
        while True:
            size_line = await asyncio.wait_for(reader.readline(), IDLE_TIMEOUT)
            size = int(size_line.split(b";", 1)[0].strip() or b"0", 16)
            if size == 0:
                while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                    pass
                return bytes(out)
            out += await asyncio.wait_for(reader.readexactly(size), IDLE_TIMEOUT)
            await reader.readline()
            if len(out) > MAX_BODY:
                raise ValueError("request body too large")
    length = head.header("content-length")
    if length:
        n = int(length)
        if n > MAX_BODY:
            raise ValueError("request body too large")
        return await asyncio.wait_for(reader.readexactly(n), IDLE_TIMEOUT)
    return b""


def _split_hostport(s: str, default: int) -> tuple[str, int]:
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default
    host, sep, port = s.rpartition(":")
    if sep and port.isdigit():
        return host, int(port)
    return s, default


def _no_proxy_match(host: str, no_proxy: list[str]) -> bool:
    for entry in no_proxy:
        e = entry.strip().lower().lstrip(".")
        if not e:
            continue
        if e == "*" or host == e or host.endswith("." + e):
            return True
    return False


class Edge:
    def __init__(self, decider: Decider, vault: Vault, ca: LocalCA, *, control_token: str,
                 upstream_proxy: str | None = None, no_proxy: list[str] | None = None, upstream_cafile: str | None = None,
                 stand_ins: dict[str, tuple[str, int]] | None = None, on_event: Callable[[dict], None] | None = None):
        self.decider, self.vault, self.ca = decider, vault, ca
        self.control_token = control_token
        self.upstream_proxy = upstream_proxy
        self.no_proxy = no_proxy or []
        self.stand_ins = {k.lower(): v for k, v in (stand_ins or {}).items()}
        self.on_event = on_event or (lambda e: None)
        self.upstream_ctx = ssl.create_default_context(cafile=upstream_cafile) if upstream_cafile else ssl.create_default_context()
        self.upstream_ctx.set_alpn_protocols(["http/1.1"])
        self.port = 0
        self.stats = {"allowed": 0, "blocked": 0, "passed_reads": 0}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.base_events.Server | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

    # --- lifecycle --------------------------------------------------------------------------------------
    def start(self) -> int:
        self._thread = threading.Thread(target=self._run, name="airlock-edge", daemon=True)
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("the Airlock edge did not start")
        return self.port

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        async def main() -> None:
            self._server = await asyncio.start_server(self._client, "127.0.0.1", 0, limit=1 << 20)
            self.port = self._server.sockets[0].getsockname()[1]
            self._ready.set()
            async with self._server:
                await self._server.serve_forever()

        try:
            self._loop.run_until_complete(main())
        except (asyncio.CancelledError, RuntimeError):
            pass

    def stop(self) -> None:
        if self._loop and self._server:
            self._loop.call_soon_threadsafe(self._server.close)
            for task in asyncio.all_tasks(self._loop):
                self._loop.call_soon_threadsafe(task.cancel)
        if self._thread:
            self._thread.join(5)

    # --- connection handling ----------------------------------------------------------------------------
    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await _read_head(reader)
            if head is None:
                return
            if head.method == "CONNECT":
                host, port = _split_hostport(head.target, 443)
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                await writer.start_tls(self.ca.server_context(host))
                inner = await _read_head(reader)
                if inner is not None:
                    await self._serve(inner, reader, writer, "https", host.lower(), port)
            elif head.target.startswith("/"):
                await self._control(head, reader, writer)
            else:
                u = urlsplit(head.target)
                host = (u.hostname or "").lower()
                port = u.port or (443 if u.scheme == "https" else 80)
                path = u.path or "/"
                if u.query:
                    path += "?" + u.query
                await self._serve(RequestHead(head.method, path, head.version, head.headers), reader, writer,
                                  u.scheme or "http", host, port)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError, ssl.SSLError, ValueError):
            pass
        except asyncio.CancelledError:
            raise
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _serve(self, head: RequestHead, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                     scheme: str, host: str, port: int) -> None:
        if (head.header("expect") or "").lower() == "100-continue":
            writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            await writer.drain()
        body = await _read_body(reader, head)
        default_port = 443 if scheme == "https" else 80
        netloc = host if port == default_port else f"{host}:{port}"
        url = f"{scheme}://{netloc}{head.target}"
        headers = [(k, v) for k, v in head.headers if k.lower() not in HOP_BY_HOP and k.lower() != "host"]

        body_text = body.decode("latin-1") if body else ""
        creds = self.vault.placeholders_in(url, body_text, *[v for _, v in headers])
        facts = self._facts(head.method, url, body)
        stray = [c for c in creds if not self.vault.allowed_for(c, host)]
        if stray:
            auth = Authorization(False, f"credential {', '.join(stray)} may only be sent to "
                                        f"{', '.join(self.vault.bindings[stray[0]])}", facts)
            await self._refuse(writer, auth, creds)
            return
        consequential = not classify_http(head.method, url).read_only or bool(creds)
        if not consequential:
            self.stats["passed_reads"] += 1
            await self._forward(writer, head.method, host, port, scheme, head.target, headers, body, auth=None, creds=[])
            return

        auth = self.decider.authorize(facts)
        if not auth.allowed:
            await self._refuse(writer, auth, creds)
            return
        # Step 5: the request about to be sent is rebuilt from the exact bytes and verified against the proof.
        final = self._facts(head.method, url, body)
        try:
            self.decider.verify(auth, final)
        except Exception as exc:  # noqa: BLE001 - any verification failure refuses
            auth.allowed = False
            auth.reason = f"proof verification failed at the edge: {type(exc).__name__}: {exc}"
            await self._refuse(writer, auth, creds)
            return
        await self._forward(writer, head.method, host, port, scheme, head.target, headers, body, auth=auth, creds=creds)

    def _facts(self, method: str, url: str, body: bytes) -> ActionFacts:
        a = classify_http(method, url)
        return ActionFacts(
            kind="http", action=a.action, resource=a.resource,
            params={"method": method.upper(), "url": url, "body_sha256": body_digest(body)},
            display={"method": method.upper(), "url": self.vault.redact(url), "body_bytes": len(body)},
        )

    async def _refuse(self, writer: asyncio.StreamWriter, auth: Authorization, creds: list[str]) -> None:
        receipt = self.decider.record(auth, executed=False, credentials=creds)
        self.stats["blocked"] += 1
        self.on_event({"decision": "BLOCKED", "receipt": receipt.to_dict()})
        payload = json.dumps({
            "error": "blocked_by_airlock", "action": auth.facts.action, "target": auth.facts.resource,
            "reason": auth.reason, "credential_released": False, "execution_occurred": False, "receipt": receipt.id,
        }).encode()
        writer.write(
            b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nX-Airlock-Decision: BLOCKED\r\n"
            + f"X-Airlock-Receipt: {receipt.id}\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
            + payload
        )
        await writer.drain()

    async def _open_upstream(self, scheme: str, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        if host in self.stand_ins:
            h, p = self.stand_ins[host]
            r, w = await asyncio.open_connection(h, p)
            return r, w, "stand-in"
        tls = scheme == "https"
        if self.upstream_proxy and not _no_proxy_match(host, self.no_proxy):
            pu = urlsplit(self.upstream_proxy)
            r, w = await asyncio.open_connection(pu.hostname, pu.port or 80)
            if tls:
                w.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
                await w.drain()
                status = await r.readline()
                while (await r.readline()) not in (b"\r\n", b"\n", b""):
                    pass
                if b" 200" not in status:
                    raise ConnectionError(f"upstream proxy refused CONNECT {host}: {status[:60]!r}")
                await w.start_tls(self.upstream_ctx, server_hostname=host)
            return r, w, "real"
        if tls:
            r, w = await asyncio.open_connection(host, port, ssl=self.upstream_ctx, server_hostname=host)
        else:
            r, w = await asyncio.open_connection(host, port)
        return r, w, "real"

    async def _forward(self, writer: asyncio.StreamWriter, method: str, host: str, port: int, scheme: str, target: str,
                       headers: list[tuple[str, str]], body: bytes, *, auth: Authorization | None, creds: list[str]) -> None:
        out_target = self.vault.inject(target, creds) if creds else target
        if creds and body:
            body = self.vault.inject(body.decode("latin-1"), creds).encode("latin-1")
        out_headers = [(k, self.vault.inject(v, creds) if creds else v) for k, v in headers if k.lower() != "content-length"]
        default_port = 443 if scheme == "https" else 80
        host_header = host if port == default_port else f"{host}:{port}"
        lines = [f"{method} {out_target} HTTP/1.1", f"Host: {host_header}"] + [f"{k}: {v}" for k, v in out_headers]
        if body or method in ("POST", "PUT", "PATCH"):
            lines.append(f"Content-Length: {len(body)}")
        lines.append("Connection: close")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body
        try:
            ur, uw, upstream = await self._open_upstream(scheme, host, port)
        except (OSError, ssl.SSLError, ConnectionError) as exc:
            if auth is not None:
                rec = self.decider.record(auth, executed=False, credentials=[], reason=f"upstream unreachable: {exc}")
                self.on_event({"decision": "ERROR", "receipt": rec.to_dict()})
            msg = f"Airlock edge could not reach {host}: {exc}".encode()
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                         + f"Content-Length: {len(msg)}\r\n\r\n".encode() + msg)
            await writer.drain()
            return
        status = 0
        try:
            uw.write(raw)
            await uw.drain()
            first = await asyncio.wait_for(ur.readline(), IDLE_TIMEOUT)
            try:
                status = int(first.split(b" ", 2)[1])
            except (IndexError, ValueError):
                status = 0
            writer.write(first)
            while True:
                chunk = await asyncio.wait_for(ur.read(65536), IDLE_TIMEOUT)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
        finally:
            uw.close()
            if auth is not None:
                rec = self.decider.record(auth, executed=True, result={"status": status}, credentials=creds, upstream=upstream)
                self.stats["allowed"] += 1
                self.on_event({"decision": "ALLOWED", "receipt": rec.to_dict()})

    # --- control API (in-process hook) ------------------------------------------------------------------
    async def _control(self, head: RequestHead, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        body = await _read_body(reader, head)
        if head.target != "/_airlock/decide" or head.header("x-airlock-token") != self.control_token:
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        req = json.loads(body or b"{}")
        facts = ActionFacts(kind=req.get("kind", "filesystem"), action=req["action"], resource=req.get("resource"),
                            params=req.get("params", {}), display=req.get("display", {}))
        if req.get("protected"):
            auth = Authorization(False, req.get("reason") or "an agent may not change its own authority", facts)
        else:
            auth = self.decider.authorize(facts)
            if auth.allowed:
                try:
                    self.decider.verify(auth, facts)
                except Exception as exc:  # noqa: BLE001
                    auth.allowed = False
                    auth.reason = f"proof verification failed: {exc}"
        rec = self.decider.record(auth, executed=auth.allowed, result={"performed_by": "agent process"} if auth.allowed else None)
        self.stats["allowed" if auth.allowed else "blocked"] += 1
        self.on_event({"decision": "ALLOWED" if auth.allowed else "BLOCKED", "receipt": rec.to_dict()})
        payload = json.dumps({"allowed": auth.allowed, "reason": auth.reason, "receipt": rec.id}).encode()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode() + payload)
        await writer.drain()


def upstream_settings(env: dict[str, str]) -> tuple[str | None, list[str], str | None]:
    """Upstream proxy, NO_PROXY list and CA file the edge itself should use (from Airlock's own environment)."""
    proxy = env.get("HTTPS_PROXY") or env.get("https_proxy") or env.get("HTTP_PROXY") or env.get("http_proxy")
    no_proxy = (env.get("NO_PROXY") or env.get("no_proxy") or "").split(",")
    cafile = env.get("AIRLOCK_UPSTREAM_CA_FILE") or env.get("SSL_CERT_FILE") or env.get("REQUESTS_CA_BUNDLE")
    if cafile and not os.path.exists(cafile):
        cafile = None
    return proxy, [n for n in no_proxy if n.strip()], cafile
