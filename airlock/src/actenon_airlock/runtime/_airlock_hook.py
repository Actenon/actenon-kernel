"""In-process enforcement for Python agents started by ``airlock run``.

An interpreter audit hook (PEP 578; it cannot be removed once installed) sees file writes and deletes,
process execution and outgoing TCP connections at the moment they happen, with their real arguments.
Each consequential one is decided by the Airlock edge (approved manifest -> Permit -> kernel proof); a
refusal raises ``PermissionError`` before the operation runs. If the edge cannot be reached, the hook
fails closed.

Not consequential (never asked): reads, directory creation, the temporary directory, user caches,
bytecode caches, /dev, /proc, /sys, the interpreter's own installation, and loopback connections
(the edge itself listens on loopback). The agent may never write ``airlock.json`` or ``.airlock/``.
"""

from __future__ import annotations

import http.client
import json
import os
import shlex
import socket
import sys
import tempfile
import threading

_state = threading.local()
_EDGE = os.environ.get("AIRLOCK_EDGE", "")
_TOKEN = os.environ.get("AIRLOCK_TOKEN", "")
_ROOT = os.path.realpath(os.environ.get("AIRLOCK_PROJECT_ROOT", os.getcwd()))
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC


def _scratch_roots() -> list[str]:
    roots = [tempfile.gettempdir(), "/tmp", "/var/tmp", "/dev", "/proc", "/sys", os.path.expanduser("~/.cache"),
             sys.prefix, sys.base_prefix, sys.exec_prefix]
    extra = os.environ.get("AIRLOCK_SCRATCH_DIRS", "")
    roots += [p for p in extra.split(os.pathsep) if p]
    return [os.path.realpath(r) for r in roots if r]


_SCRATCH = _scratch_roots()
_PROTECTED = [os.path.join(_ROOT, "airlock.json"), os.path.join(_ROOT, ".airlock")]


def _decide(payload: dict) -> dict:
    host, _, port = _EDGE.rpartition(":")
    _state.busy = True
    try:
        conn = http.client.HTTPConnection(host, int(port), timeout=60)
        body = json.dumps(payload)
        conn.request("POST", "/_airlock/decide", body, {"Content-Type": "application/json", "X-Airlock-Token": _TOKEN})
        resp = conn.getresponse()
        data = json.loads(resp.read() or b"{}")
        conn.close()
        return data
    except Exception as exc:  # noqa: BLE001 - fail closed
        return {"allowed": False, "reason": f"the Airlock edge could not be reached ({type(exc).__name__}); failing closed"}
    finally:
        _state.busy = False


def _refuse(action: str, target: str, verdict: dict) -> None:
    raise PermissionError(
        f"Airlock BLOCKED {action} {target}: {verdict.get('reason', 'not approved')}. "
        f"Credential released: NO. Execution occurred: NO. Receipt: {verdict.get('receipt', '-')}"
    )


def _path_resource(path) -> tuple[str, str] | None:
    """(resource, absolute path) for a consequential path, or None for scratch/unknown paths."""
    if isinstance(path, int):
        return None
    if isinstance(path, bytes):
        path = os.fsdecode(path)
    try:
        full = os.path.realpath(os.path.abspath(str(path)))
    except (OSError, ValueError):
        return None
    if "/__pycache__/" in full or full.endswith(".pyc"):
        return None
    # The project comes first: a project that happens to live under /tmp is still the project.
    if full == _ROOT or full.startswith(_ROOT + os.sep):
        rel = os.path.relpath(full, _ROOT).replace(os.sep, "/")
        if any(full == r or full.startswith(r + os.sep) for r in _SCRATCH if r.startswith(_ROOT + os.sep)):
            return None  # a virtualenv or cache inside the project
        return "./" + rel, full
    for root in _SCRATCH:
        if full == root or full.startswith(root + os.sep):
            return None
    return full, full


def _is_protected(full: str) -> bool:
    return any(full == p or full.startswith(p + os.sep) for p in _PROTECTED)


def _check_path(action: str, path) -> None:
    res = _path_resource(path)
    if res is None:
        return
    resource, full = res
    payload = {"kind": "filesystem", "action": action, "resource": resource,
               "params": {"path": resource, "op": action}, "display": {"path": full}}
    if _is_protected(full):
        payload.update(protected=True, reason="an agent may not change its own authority (airlock.json / .airlock)")
    verdict = _decide(payload)
    if not verdict.get("allowed"):
        _refuse(action, resource, verdict)


def _program(executable, args) -> str:
    prog = executable
    if not prog:
        if isinstance(args, (list, tuple)) and args:
            prog = args[0]
        elif isinstance(args, (str, bytes)):
            parts = shlex.split(os.fsdecode(args)) if args else []
            prog = parts[0] if parts else ""
    prog = os.fsdecode(prog) if isinstance(prog, bytes) else str(prog or "")
    return os.path.basename(prog)


def _check_exec(executable, args) -> None:
    prog = _program(executable, args)
    argv = [os.fsdecode(a) if isinstance(a, bytes) else str(a) for a in (args if isinstance(args, (list, tuple)) else [args])]
    verdict = _decide({"kind": "process", "action": "process.exec", "resource": prog or None,
                       "params": {"program": prog, "argv": argv}, "display": {"argv": argv}})
    if not verdict.get("allowed"):
        _refuse("process.exec", prog or "(unknown program)", verdict)


def _loopback(host: str) -> bool:
    return host in ("localhost", "::1") or host.startswith("127.") or host == "0.0.0.0"


def _check_connect(sock, address) -> None:
    try:
        if sock.family not in (socket.AF_INET, socket.AF_INET6) or sock.type != socket.SOCK_STREAM:
            return
    except Exception:  # noqa: BLE001
        return
    if not isinstance(address, tuple) or not address:
        return
    host, port = str(address[0]), address[1] if len(address) > 1 else 0
    if _loopback(host):
        return
    verdict = _decide({"kind": "network", "action": "network.connect", "resource": f"{host}:{port}",
                       "params": {"host": host, "port": port}, "display": {"host": host, "port": port},
                       "protected": True,
                       "reason": "direct network connection that bypasses the Airlock edge (only proxied requests can be authorised)"})
    if not verdict.get("allowed"):
        _refuse("network.connect", f"{host}:{port}", verdict)


def _hook(event: str, args: tuple) -> None:
    if getattr(_state, "busy", False):
        return
    try:
        if event == "open":
            path, mode, flags = args
            writes = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (mode is None and isinstance(flags, int) and flags & _WRITE_FLAGS)
            if writes:
                _check_path("filesystem.write", path)
        elif event in ("os.remove", "os.rmdir", "shutil.rmtree"):
            _check_path("filesystem.delete", args[0])
        elif event == "os.rename":
            _check_path("filesystem.delete", args[0])
            _check_path("filesystem.write", args[1])
        elif event == "os.truncate":
            _check_path("filesystem.write", args[0])
        elif event == "subprocess.Popen":
            _check_exec(args[0], args[1])
        elif event == "os.system":
            _check_exec(None, args[0])
        elif event in ("os.exec", "os.posix_spawn"):
            _check_exec(args[0], args[1])
        elif event == "os.spawn":
            _check_exec(args[1], args[2])
        elif event == "socket.connect":
            _check_connect(args[0], args[1])
    except PermissionError:
        raise
    except Exception:  # noqa: BLE001 - never let the hook itself crash the agent
        return


_installed = False


def install() -> None:
    global _installed
    if _installed or not _EDGE or not _TOKEN:
        return
    _installed = True
    sys.addaudithook(_hook)
