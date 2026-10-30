"""nwaccel — интеграция C-ядра (nwaccel.c) в netwatch.

C-бинарь ускоряет два горячих пути:
  * flood/raw ICMP-пинг (non-blocking send/recv, несколько сокетов, mdev/p50/p95);
  * пакетное DNS-разрешение (пул pthread вместо последовательного getaddrinfo).

Всё через subprocess + JSON: никаких ABI-рисков и ctypes. Если gcc/бинарь
недоступны или ОС не Linux — прозрачный фолбэк на Python-реализацию.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple

IS_SUPPORTED = platform.system() in ("Linux", "Windows")
_HERE = Path(__file__).resolve().parent
_SRC = _HERE / "nwaccel.c"
_BIN_NAMES = ("nwaccel.exe", "nwaccel") if platform.system() == "Windows" \
    else ("nwaccel", "nwaccel.exe")

_lock = threading.Lock()
_bin_cache: Optional[Path] = None
_probe_failed = False


def find_binary() -> Optional[Path]:
    """Готовый бинарь рядом со скриптом / в PATH; иначе None."""
    env = os.environ.get("NWACCEL_BIN")
    cands: List[Path] = []
    if env:
        cands.append(Path(env))
    for name in _BIN_NAMES:
        cands.append(_HERE / name)
        which = shutil.which(name)
        if which:
            cands.append(Path(which))
    for p in cands:
        try:
            if p.is_file() and os.access(p, os.X_OK):
                return p
        except OSError:
            pass
    return None


def build_binary(quiet: bool = True) -> Optional[Path]:
    """gcc -O2 -pthread nwaccel.c -> ./nwaccel. None если собрать нельзя."""
    global _bin_cache, _probe_failed
    with _lock:
        if _bin_cache is not None:
            return _bin_cache
        if not IS_SUPPORTED or _probe_failed:
            return None
        existing = find_binary()
        if existing:
            _bin_cache = existing
            return existing
        cc = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc") \
            or shutil.which("clang")
        if not cc or not _SRC.is_file():
            if not quiet:
                print("nwaccel: компилятор (cc/gcc/clang) или nwaccel.c не найдены",
                      file=sys.stderr)
            _probe_failed = True
            return None
        out = _HERE / "nwaccel"
        cmd = [cc, "-O2", "-pthread", "-o", str(out), str(_SRC)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                if not quiet:
                    print("nwaccel: сборка не удалась:\n" + (r.stderr or "")[:800],
                          file=sys.stderr)
                _probe_failed = True
                return None
        except (OSError, subprocess.TimeoutExpired) as e:
            if not quiet:
                print(f"nwaccel: сборка невозможна: {e}", file=sys.stderr)
            _probe_failed = True
            return None
        _bin_cache = out
        return out


def available(auto_build: bool = False) -> bool:
    b = find_binary()
    if b is None and auto_build:
        b = build_binary()
    return b is not None


def _run(args: List[str], timeout: float) -> Optional[dict]:
    b = find_binary()
    if b is None:
        return None
    try:
        r = subprocess.run([str(b)] + args, capture_output=True, text=True,
                           timeout=timeout)
        line = (r.stdout or "").strip().splitlines()
        if r.returncode != 0 or not line:
            return None
        return json.loads(line[-1])
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


# --------------------------------------------------------------------- ping --

def c_ping(host: str, count: int = 4, interval_ms: int = 250, size: int = 56,
           df: bool = False, ttl: Optional[int] = None, sockets: int = 1,
           timeout: float = 8.0) -> Optional[dict]:
    """Flood/raw ICMP через C-ядро. Возвращает dict статистики или None (фолбэк)."""
    args = ["ping", host, "--count", str(count), "--interval", str(interval_ms),
            "--size", str(size), "--sockets", str(sockets)]
    if df:
        args.append("--df")
    if ttl:
        args += ["--ttl", str(ttl)]
    d = _run(args, timeout + 2.0)
    if d is None or d.get("error") == "raw_not_allowed":
        return None
    return d


# --------------------------------------------------------------------- dns ---

def c_dns_resolve_many(hosts: List[str], threads: int = 16,
                       timeout: float = 10.0) -> Optional[Dict[str, dict]]:
    """Пакетное разрешение хостов в пуле потоков C. {host: {ok, ips, ms, error?}}."""
    if not hosts:
        return {}
    d = _run(["dns", ",".join(hosts), "--threads", str(threads)], timeout)
    if d is None:
        return None
    return {r["host"]: r for r in d.get("results", [])}


# ------------------------------------------------------------------ report ---

def engine_status(auto_build: bool = False) -> dict:
    b = find_binary()
    built = False
    if b is None and auto_build:
        b = build_binary()
        built = b is not None
    status = "ready" if b else "missing"
    usable = False
    if b:
        # проверим что raw-сокеты реально можно открывать (root/CAP_NET_RAW)
        d = _run(["ping", "127.0.0.1", "--count", "1", "--interval", "10"], 5.0)
        usable = d is not None and "error" not in d
    return {"binary": str(b) if b else None, "status": status,
            "built_now": built, "icmp_usable": usable,
            "platform_ok": IS_SUPPORTED}
