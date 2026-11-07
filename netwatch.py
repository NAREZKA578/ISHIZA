#!/usr/bin/env python3
"""
netwatch — монитор сетевых ошибок и проблем подключения (чистый stdlib, Python 3.8+).

Что умеет:
  * ICMP-пинг целей; если ICMP недоступен/блокируется — автоматический TCP-фолбэк;
  * TCP-хендшейк к host:port (ловит timeout / refused / unreachable);
  * HTTP(S)-пробы с замером TTFB и реакцией на 5xx;
  * Метрики: RTT (last/avg/max), jitter, % потерь, счётчик последовательных фейлов;
  * Детект DNS-ошибок, таймаутов, TLS-проблем;
  * Наблюдение за маршрутизацией: обрыв default route, смена интерфейса/шлюза;
  * Порог «медленно» (DEGRADED) и переходы UP/DOWN/DEGRADED как события;
  * Логи: JSONL событий + CSV всех проб; live-дашборд; отчёт по логу (--report);
  * Алерты: терминал + Telegram bot API + generic webhook.

Примеры:
  python3 netwatch.py --targets 8.8.8.8 https://example.com db.internal:5432
  python3 netwatch.py --config netwatch.toml --dashboard
  python3 netwatch.py --targets 1.1.1.1 --duration 60 --csv probes.csv
  python3 netwatch.py --report netwatch-events.jsonl
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import struct
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple, List

try:
    import nw_probes as P          # расширенные пробники (v2)
except Exception:                  # библиотека потеряна — работаем в режиме v1
    P = None

try:
    import nwaccel as A            # C-ядро: flood-ping + пакетный DNS (опционально)
except Exception:
    A = None

# Глобальные настройки C-ядра (включает main() при --c-core / --c-build).
ACCEL = {"on": False, "interval_ms": 100, "sockets": 1}


# -----------------------------------------------------------------------------
# Цветной вывод
# -----------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def ok(t):   return c(t, "32")
def warn(t): return c(t, "33")
def bad(t):  return c(t, "31")
def dim(t):  return c(t, "2")
def bold(t): return c(t, "1")
def cyan(t): return c(t, "36")


def now_iso() -> str:
    lt = time.localtime()
    return time.strftime("%Y-%m-%dT%H:%M:%S", lt) + time.strftime("%z", lt)[:3]


# -----------------------------------------------------------------------------
# Конфигурация цели
# -----------------------------------------------------------------------------

@dataclass
class TargetConfig:
    name: str
    host: Optional[str] = None        # имя/IP для ping/TCP
    url: Optional[str] = None         # http(s) URL для HTTP-пробы
    port: Optional[int] = None        # TCP-порт
    interval: float = 5.0             # период проб, сек
    timeout: float = 2.0              # таймаут пробы, сек
    latency_warn_ms: float = 250.0    # порог DEGRADED
    fails_to_down: int = 2            # сколько фейлов подряд считать DOWN
    jitter_warn_ms: float = 80.0      # порог тревоги по джиттеру
    loss_warn_pct: float = 20.0       # порог тревоги по потерям в окне
    mode: str = "auto"                # auto|icmp|tcp|http|https|tls|dns|udp|ntp
    expect_status: Optional[int] = None   # ожидаемый HTTP-код (иначе >=500 = ошибка)
    dns_server: Optional[str] = None      # резолвить через конкретный сервер
    baseline: bool = True                 # строить ли EWMA-базу «нормы»
    verify_tls: bool = True

    def describe(self) -> str:
        if self.url:
            return self.url
        if self.port:
            return f"{self.host}:{self.port}"
        return self.host or self.name


MODE_SCHEMES = {"http": "http", "https": "https", "tls": "tls", "ssl": "tls",
                "tcp": "tcp", "udp": "udp", "dns": "dns", "ntp": "ntp",
                "icmp": "icmp", "ping": "icmp"}


def parse_target(spec: str, defaults: TargetConfig) -> TargetConfig:
    """'alias:host:443' | 'https://site/path' | 'host:443' | 'host' |
       'tls:host:443' | 'udp:host:161' | 'dns:name@server' | 'ntp:pool.ntp.org'."""
    name, rest = None, spec
    m = re.match(r"^([A-Za-z][A-Za-z0-9_-]*):(.+)$", spec)
    cand_mode = None
    if m and not spec.startswith(("http://", "https://")):
        cand_alias, cand_rest = m.group(1), m.group(2)
        low = cand_alias.lower()
        if low in MODE_SCHEMES and not re.match(r"^\d+$", cand_rest):
            # tls:host:443 / udp:host:53 — это режим, а не алиас
            cand_mode, rest = MODE_SCHEMES[low], cand_rest
        elif ":" in cand_rest or "/" in cand_rest or cand_rest[0].isdigit():
            name, rest = cand_alias, cand_rest
        elif not re.match(r"^\d+$", cand_rest):
            name, rest = cand_alias, cand_rest

    t = TargetConfig(name=name or "")
    for f in ("interval", "timeout", "latency_warn_ms", "fails_to_down",
              "jitter_warn_ms", "loss_warn_pct", "baseline", "verify_tls"):
        setattr(t, f, getattr(defaults, f))

    if rest.startswith(("http://", "https://")):
        pr = urllib.parse.urlparse(rest)
        t.url = rest
        t.host = pr.hostname
        t.port = pr.port or (443 if pr.scheme == "https" else 80)
        t.mode = "http" if pr.scheme == "http" else "https"
    elif rest.startswith("dns:") or cand_mode == "dns":
        body = rest[4:] if rest.startswith("dns:") else rest
        if "@" in body:
            qname, srv = body.split("@", 1)
            t.dns_server = srv
        else:
            qname = body
        t.url = qname          # имя для запроса (может содержать точки/слэши)
        t.host = qname.split("/")[0]
        t.mode = "dns"
    elif cand_mode:
        t.mode = cand_mode
        if ":" in rest and rest.rsplit(":", 1)[-1].isdigit():
            t.host, p = rest.rsplit(":", 1)
            t.port = int(p)
        else:
            t.host = rest
        if cand_mode in ("http", "https") and not t.url and t.host:
            t.url = f"{cand_mode}://{t.host}" + (f":{t.port}" if t.port else "")
    elif ":" in rest and rest.rsplit(":", 1)[-1].isdigit():
        t.host, p = rest.rsplit(":", 1)
        t.port = int(p)
    else:
        t.host = rest
    if not t.name:
        t.name = t.describe() if cand_mode != "dns" else f"dns:{t.host}"
    return t


# -----------------------------------------------------------------------------
# Пробники: возвращают (rtt_ms|None, error|None)
# -----------------------------------------------------------------------------

def icmp_ping(host: str, timeout: float) -> Optional[float]:
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout)))), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout + 2).stdout
        m = re.search(r"time[=<]\s*([\d.]+)\s*ms", out)
        return float(m.group(1)) if m else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def tcp_connect(host: str, port: int, timeout: float) -> Tuple[Optional[float], Optional[str]]:
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return None, f"dns_error: {e.strerror or e}"
    start = time.monotonic()
    err = None
    for family, stype, proto, _canon, sa in infos:
        s = socket.socket(family, stype, proto)
        s.settimeout(timeout)
        try:
            s.connect(sa)
            return (time.monotonic() - start) * 1000.0, None
        except socket.timeout:
            err = "connect_timeout"
        except ConnectionRefusedError:
            # порт закрыт, но хост отвечает — считаем reachable c предупреждением
            return (time.monotonic() - start) * 1000.0, "connection_refused"
        except OSError as e:
            err = f"net_error: {e.strerror or e}"
        finally:
            s.close()
    return None, err


def http_probe(url: str, timeout: float) -> Tuple[Optional[float], Optional[int], Optional[str]]:
    req = urllib.request.Request(url, headers={"User-Agent": "netwatch/1.0"})
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return (time.monotonic() - start) * 1000.0, resp.status, None
    except urllib.error.HTTPError as e:
        return (time.monotonic() - start) * 1000.0, e.code, None
    except socket.timeout:
        return None, None, "http_timeout"
    except ssl.SSLCertVerificationError as e:
        return None, None, f"tls_error: {e.verify_message if hasattr(e, 'verify_message') else e}"
    except urllib.error.URLError as e:
        reason = str(e.reason)
        low = reason.lower()
        if "name resolution" in low or "getaddrinfo" in low or "nodename" in low:
            return None, None, f"dns_error: {reason[:120]}"
        if "timed out" in low:
            return None, None, "http_timeout"
        if "ssl" in low or "certificate" in low:
            return None, None, f"tls_error: {reason[:120]}"
        return None, None, f"http_error: {reason[:120]}"
    except Exception as e:
        return None, None, f"http_error: {type(e).__name__}: {str(e)[:120]}"


# -----------------------------------------------------------------------------
# Скользящая статистика
# -----------------------------------------------------------------------------

@dataclass
class Stats:
    window: int = 36                  # ~3 минуты при интервале 5с
    total: int = 0
    failures: int = 0
    consec_fails: int = 0
    last_ok: Optional[float] = None
    max_rtt: float = 0.0
    rtts: List[float] = field(default_factory=list)
    fail_flags: List[bool] = field(default_factory=list)

    def add(self, rtt: Optional[float]):
        self.total += 1
        failed = rtt is None
        self.failures += 1 if failed else 0
        self.consec_fails = self.consec_fails + 1 if failed else 0
        if rtt is not None:
            self.last_ok = rtt
            self.max_rtt = max(self.max_rtt, rtt)
            self.rtts.append(rtt)
        self.fail_flags.append(failed)
        self.rtts = self.rtts[-self.window:]
        self.fail_flags = self.fail_flags[-self.window:]

    def percentile(self, p: float) -> Optional[float]:
        """p-й перцентиль RTT по окну (0..100)."""
        if not self.rtts:
            return None
        s = sorted(self.rtts)
        k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
        return s[k]

    @property
    def avg_rtt(self) -> float:
        return sum(self.rtts) / len(self.rtts) if self.rtts else 0.0

    @property
    def jitter(self) -> Optional[float]:
        w = self.rtts[-10:]
        if len(w) < 2:
            return None
        return sum(abs(b - a) for a, b in zip(w, w[1:])) / (len(w) - 1)

    @property
    def win_loss_pct(self) -> float:
        if not self.fail_flags:
            return 0.0
        return 100.0 * sum(self.fail_flags) / len(self.fail_flags)

    @property
    def total_loss_pct(self) -> float:
        return 100.0 * self.failures / self.total if self.total else 0.0

    def snapshot(self) -> dict:
        return {
            "total": self.total,
            "failures": self.failures,
            "loss_pct": round(self.total_loss_pct, 1),
            "win_loss_pct": round(self.win_loss_pct, 1),
            "avg_ms": round(self.avg_rtt, 1),
            "last_ms": round(self.last_ok, 1) if self.last_ok is not None else None,
            "max_ms": round(self.max_rtt, 1),
            "p95_ms": round(self.percentile(95), 1) if self.percentile(95) else None,
            "jitter_ms": round(self.jitter, 1) if self.jitter is not None else None,
            "consec_fails": self.consec_fails,
        }


# -----------------------------------------------------------------------------
# EWMA-база «нормы» + детект аномалий (v2)
# -----------------------------------------------------------------------------

class Baseline:
    """Экспоненциальное сглаживание RTT. После прогрева (~10 сэмплов) считаем
    аномалией отклонение больше max(k*sigma, min_abs_delta)."""

    def __init__(self, alpha: float = 0.25, k: float = 4.0, min_abs_ms: float = 50.0):
        self.alpha, self.k, self.min_abs = alpha, k, min_abs_ms
        self.mean: Optional[float] = None
        self.var: float = 0.0
        self.n: int = 0

    @property
    def ready(self) -> bool:
        return self.n >= 10 and self.mean is not None

    def update(self, x: float) -> Tuple[bool, str]:
        """Возвращает (is_anomaly, описание). Сам среднее аномалии не портят."""
        if self.mean is None:
            self.mean, self.n = x, 1
            return False, ""
        dev = x - self.mean
        sigma = self.var ** 0.5
        thresh = max(self.k * sigma, self.min_abs)
        anomaly = self.ready and abs(dev) > thresh
        if not anomaly:  # робастное обновление: выбросы базу не сдвигают
            self.mean += self.alpha * dev
            self.var = (1 - self.alpha) * (self.var + self.alpha * dev * dev)
        self.n += 1
        if anomaly:
            direction = "SPIKE" if dev > 0 else "DROP"
            return True, f"{direction}: rtt={x:.0f}ms vs baseline {self.mean:.0f}±{sigma:.0f}ms"
        return False, ""


# -----------------------------------------------------------------------------
# События, логи, алерты
# -----------------------------------------------------------------------------

@dataclass
class AlertConfig:
    telegram_token: Optional[str] = None
    telegram_chat: Optional[str] = None
    webhook_url: Optional[str] = None
    min_level: str = "CRIT"           # CRIT | WARN


class EventBus:
    LEVELS = {"INFO": 0, "WARN": 1, "CRIT": 2}

    def __init__(self, log_path: Optional[Path], alerts: AlertConfig):
        self.log_fp = open(log_path, "a", encoding="utf-8") if log_path else None
        self.alerts = alerts
        self._lock = threading.Lock()
        self._rate: dict = {}

    def emit(self, level: str, target: str, kind: str, msg: str, extra: dict = None,
             rate_limit: float = 0.0):
        # rate_limit: минимальный интервал между одинаковыми (target, kind), сек
        if rate_limit > 0:
            key = (target, kind)
            now = time.monotonic()
            with self._lock:
                last = self._rate.get(key, 0.0)
                if now - last < rate_limit:
                    return
                self._rate[key] = now
        ev = {"ts": now_iso(), "level": level, "target": target,
              "kind": kind, "msg": msg, **(extra or {})}
        line = json.dumps(ev, ensure_ascii=False)
        with self._lock:
            if self.log_fp:
                self.log_fp.write(line + "\n")
                self.log_fp.flush()
        self._print(ev)
        if self.LEVELS.get(level, 9) >= self.LEVELS[self.alerts.min_level]:
            self._alert_async(ev)

    def _print(self, ev: dict):
        tag = {"INFO": ok("INFO "), "WARN": warn("WARN "), "CRIT": bad("CRIT!")}.get(
            ev["level"], ev["level"])
        print(f"[{dim(ev['ts'])}] {tag} [{bold(ev['target'])}] {ev['msg']}", flush=True)

    def _alert_async(self, ev: dict):
        a = self.alerts
        text = f"[netwatch:{ev['level']}] {ev['target']}: {ev['msg']}"
        if a.telegram_token and a.telegram_chat:
            self._spawn_post(
                f"https://api.telegram.org/bot{a.telegram_token}/sendMessage",
                json.dumps({"chat_id": a.telegram_chat, "text": text}).encode())
        if a.webhook_url:
            self._spawn_post(a.webhook_url,
                             json.dumps(ev, ensure_ascii=False).encode())

    def _spawn_post(self, url: str, body: bytes):
        threading.Thread(target=self._http_post, args=(url, body), daemon=True).start()

    @staticmethod
    def _http_post(url: str, body: bytes):
        try:
            req = urllib.request.Request(
                url, data=body, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            print(bad(f"alert delivery failed: {e}"), file=sys.stderr, flush=True)


# -----------------------------------------------------------------------------
# Системные мониторы: интерфейсы, DNS-конфиг, default route (Linux)
# -----------------------------------------------------------------------------

def read_resolv_conf() -> List[str]:
    servers = []
    try:
        for line in Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines():
            m = re.match(r"^nameserver\s+(\S+)", line.strip())
            if m:
                servers.append(m.group(1))
    except OSError:
        pass
    return servers


class RouteMonitor(threading.Thread):
    """Следит за default route (+ v2: состояние интерфейсов и /etc/resolv.conf)."""

    def __init__(self, bus: EventBus, every: float = 10.0, deep: bool = False):
        super().__init__(daemon=True)
        self.bus = bus
        self.every = every
        self.deep = deep and P is not None
        self.last_state: Optional[dict] = None
        self.last_ifaces: dict = {}
        self.last_resolv: Optional[List[str]] = None
        self.no_internet_since: Optional[float] = None
        self._portal_checked = False
        self.stop_evt = threading.Event()

    def current_state(self) -> Optional[dict]:
        if platform.system().lower() != "linux":
            return None
        try:
            out = subprocess.run(["ip", "-o", "route", "show", "default"],
                                 capture_output=True, text=True,
                                 timeout=3).stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None
        if not out:
            return {"default": False}
        parts = out.split()
        iface = parts[parts.index("dev") + 1] if "dev" in parts else "?"
        gw = parts[parts.index("via") + 1] if "via" in parts else None
        return {"default": True, "iface": iface, "gw": gw}

    def iface_states(self) -> dict:
        """{iface: state} по /sys/class/net — link_carrier + operstate."""
        states = {}
        base = Path("/sys/class/net")
        try:
            names = sorted(p.name for p in base.iterdir())
        except OSError:
            return states
        for n in names:
            if n == "lo":
                continue
            st = "unknown"
            try:
                carrier = (base / n / "carrier").read_text().strip()
                st = "up" if carrier == "1" else "down"
            except OSError:
                try:
                    oper = (base / n / "operstate").read_text().strip()
                    st = "up" if oper == "up" else "down"
                except OSError:
                    st = "no-carrier"
            states[n] = st
        return states

    def _deep_checks(self):
        # 1. обрыв/восстановление линка на интерфейсах
        cur = self.iface_states()
        for iface, st in cur.items():
            prev = self.last_ifaces.get(iface)
            if prev is not None and prev != st:
                if st == "down":
                    self.bus.emit("CRIT", "link", "iface_down",
                                  f"Интерфейс {iface} потерял линк (carrier down)")
                elif st == "up":
                    self.bus.emit("INFO", "link", "iface_up",
                                  f"Интерфейс {iface} снова в линке")
        self.last_ifaces = cur
        # 2. смена DNS-серверов (dhclient/VPN/зловред поменяли resolv.conf)
        resolv = read_resolv_conf()
        if resolv:
            if self.last_resolv is not None and set(resolv) != set(self.last_resolv):
                self.bus.emit("WARN", "system", "dns_config_changed",
                              f"/etc/resolv.conf изменён: {', '.join(self.last_resolv)} "
                              f"-> {', '.join(resolv)}")
            self.last_resolv = resolv
        # 3. общий доступ в интернет
        has, how = P.connectivity_check(timeout=min(3.0, self.every))
        if not has:
            if self.no_internet_since is None:
                self.no_internet_since = time.monotonic()
                self.bus.emit("CRIT", "system", "no_internet",
                              f"Нет доступа в интернет (проверка: example.com, причина={how})")
        elif self.no_internet_since is not None:
            dur = time.monotonic() - self.no_internet_since
            self.bus.emit("INFO", "system", "internet_restored",
                          f"Интернет снова есть ({dur:.0f}с отсутствовал, тест: {how})")
            self.no_internet_since = None
        # 4. captive portal — разово при старте
        if not self._portal_checked:
            self._portal_checked = True
            caught, info = P.captive_portal_detect()
            if caught:
                self.bus.emit("WARN", "system", "captive_portal",
                              f"Похоже за captive portal: hotspot-DNS отвечает ({info})")

    def run(self):
        while not self.stop_evt.wait(self.every):
            st = self.current_state()
            if st is not None:
                prev = self.last_state
                if st != prev:
                    if prev is not None:
                        if not st.get("default"):
                            self.bus.emit("CRIT", "routing", "route_lost",
                                          "Default route GONE — нет шлюза, связи не будет")
                        elif not prev.get("default"):
                            self.bus.emit("INFO", "routing", "route_restored",
                                          f"Default route back: via={st.get('gw')} dev={st.get('iface')}")
                        elif st.get("iface") != prev.get("iface"):
                            self.bus.emit("WARN", "routing", "route_switch",
                                          f"Route switched: dev {prev.get('iface')}({prev.get('gw')}) "
                                          f"-> {st.get('iface')}({st.get('gw')})")
                    self.last_state = st
            if self.deep:
                try:
                    self._deep_checks()
                except Exception as e:
                    self.bus.emit("WARN", "system", "monitor_error",
                                  f"deep check failed: {type(e).__name__}: {e}")


# -----------------------------------------------------------------------------
# Пробник одной цели
# -----------------------------------------------------------------------------

class Prober(threading.Thread):
    def __init__(self, cfg: TargetConfig, bus: EventBus,
                 csv_writer=None, csv_lock=None, diag_every: float = 0.0):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.bus = bus
        self.stats = Stats()
        self.baseline = Baseline() if cfg.baseline else None
        self.csv_writer = csv_writer
        self.csv_lock = csv_lock
        self.stop_evt = threading.Event()
        self.state = "UNKNOWN"
        self._reported_state = None
        self._icmp_blocked = False
        self.diag_every = diag_every          # периодический traceroute (нужен root)
        self._next_diag = time.monotonic() + diag_every if diag_every else None
        self.last_detail = ""                 # инфо для дашборда (tls/cert/…)
        self._warned_kinds = set()            # анти-спам: раз в состояние
        self._cert_warned_bucket = None

    # --- одна проба -----------------------------------------------------------
    def probe_once(self) -> Tuple[Optional[float], Optional[str]]:
        cfg = self.cfg
        # ---- расширенные режимы (v2), если nw_probes доступен
        if P is not None and cfg.mode in ("dns", "udp", "ntp", "tls"):
            return self._probe_v2()
        if cfg.url:
            if P is not None:
                ttfb, status, err, extra = P.http_probe(
                    cfg.url, cfg.timeout, expect_status=cfg.expect_status,
                    verify=cfg.verify_tls)
                det = []
                if status:
                    det.append(f"HTTP {status}")
                if extra.get("redirected_to"):
                    det.append("3xx->" + extra["redirected_to"][:60])
                self.last_detail = " ".join(det)
                return ttfb, err
            rtt, status, err = http_probe(cfg.url, cfg.timeout)
            if err is None and status is not None and status >= 500:
                err = f"http_5xx_{status}"
            elif err is None and status is not None and 400 <= status < 500:
                # сервер отвечает => сеть работает; 4xx это не сетевая проблема
                pass
            return rtt, err
        if cfg.port:
            if P is not None:
                ms, err, extra = P.tcp_probe(cfg.host, cfg.port, cfg.timeout,
                                             verify=cfg.verify_tls)
                self.last_detail = extra.get("cipher", "") or ""
                return ms, err
            return tcp_connect(cfg.host, cfg.port, cfg.timeout)
        # ICMP-цель. Приоритет: C-ядро (--c-core: flood-ping, mdev/p50/p95) →
        # raw Python (NW_ICMP=1) → /bin/ping → TCP-фолбэк.
        if ACCEL["on"] and not self._icmp_blocked and A is not None:
            d = A.c_ping(cfg.host, count=max(2, int(os.environ.get("NW_C_PING_N", "4"))),
                         interval_ms=ACCEL["interval_ms"],
                         timeout=cfg.timeout + 1,
                         sockets=ACCEL["sockets"])
            if d is not None:
                if d.get("received"):
                    self.last_detail = (f"C-core: avg={d['avg_ms']:.2f}ms "
                                        f"mdev={d['mdev_ms']:.2f} p95={d['p95_ms']:.2f} "
                                        f"loss={d['loss_pct']:.0f}% "
                                        f"({d['received']}/{d['sent']})")
                    return d["avg_ms"], None
                return None, d.get("error") or "no_icmp_reply"
            ACCEL["on"] = False   # бинарь/raw-сокеты недоступны — откат на Python
            self.bus.emit("INFO", cfg.name, "accel_disabled",
                          "C-ядро недоступно (нет root/CAP_NET_RAW?) — "
                          "фолбэк на Python-ping", rate_limit=600)
        if P is not None and os.environ.get("NW_ICMP") == "1" and not self._icmp_blocked:
            reps, perr, got = P.raw_icmp_ping(cfg.host, count=1, timeout=cfg.timeout)
            if perr == "raw_not_allowed":
                self.bus.emit("INFO", cfg.name, "raw_icmp_unavailable",
                              "NW_ICMP=1, но SOCK_RAW запрещён — работаю через /bin/ping",
                              rate_limit=300)
                os.environ["NW_ICMP"] = "0"
            elif got:
                return reps[0][1], None
            else:
                return None, perr or "no_icmp_reply"
        if not self._icmp_blocked:
            rtt = icmp_ping(cfg.host, cfg.timeout)
            if rtt is not None:
                return rtt, None
            # первый промах: проверим TCP:53 — различить «нет связи» и «ICMP режут»
            r2, e2 = tcp_connect(cfg.host, 53, cfg.timeout)
            if r2 is not None and e2 is None:
                self._icmp_blocked = True
                self.bus.emit("WARN", cfg.name, "icmp_blocked",
                              "ICMP не проходит, а TCP открыт — переключаюсь на TCP-пинг (53)")
                return r2, None
            return None, e2 or "no_icmp_reply"
        r2, e2 = tcp_connect(cfg.host, 53, cfg.timeout)
        return (r2, e2) if r2 is not None else (None, e2 or "unreachable")

    def _probe_v2(self) -> Tuple[Optional[float], Optional[str]]:
        cfg = self.cfg
        if cfg.mode == "dns":
            server = cfg.dns_server or (read_resolv_conf() or ["1.1.1.1"])[0]
            qname = (cfg.url or cfg.host).split("/")[0]
            lat, answers, err, rcode = P.dns_query(qname, server)
            self.last_detail = f"@{server} rcode={rcode}"
            if err:
                return None, f"dns_{err.lower()}"
            self.last_detail += f" answers={','.join(answers[:3])}"
            return lat, None
        if cfg.mode == "udp":
            ms, err = P.udp_echo_probe(cfg.host, cfg.port or 53, cfg.timeout)
            return ms, err
        if cfg.mode == "ntp":
            ms, offset, err = P.ntp_probe(cfg.host, cfg.timeout)
            if err:
                return ms, err
            if offset is not None and abs(offset) > 1.0:
                self.bus.emit("WARN", cfg.name, "clock_skew",
                              f"РАСХОЖДЕНИЕ ВРЕМЕНИ: локальные часы vs NTP = {offset:+.3f}s")
            self.last_detail = f"offset={offset*1000:+.1f}ms" if offset is not None else ""
            return ms, None
        if cfg.mode == "tls":
            ms, err, extra = P.tcp_probe(cfg.host, cfg.port or 443, cfg.timeout,
                                         tls=True, verify=cfg.verify_tls)
            days = extra.get("cert_days_left")
            bits = []
            if extra.get("tls"):
                bits.append(extra["tls"])
            if extra.get("tls_ms"):
                bits.append(f"hs={extra['tls_ms']:.0f}ms")
            if days is not None:
                bits.append(f"cert {days:.0f}d left")
            self.last_detail = " ".join(bits)
            if days is not None:
                bucket = "exp7" if days < 7 else ("exp30" if days < 30 else None)
                if bucket and self._cert_warned_bucket != bucket:
                    self._cert_warned_bucket = bucket
                    lvl = "CRIT" if bucket == "exp7" else "WARN"
                    self.bus.emit(lvl, cfg.name, "cert_expiring",
                                  f"TLS-сертификат истекает через {days:.0f} дней ({cfg.host}:{cfg.port or 443})")
            if err and extra.get("tls") is None and err not in ("timeout", "refused"):
                self.schedule_diagnosis()
            return ms, err
        return None, "mode_unimplemented"

    # --- диагностика при проблеме ---------------------------------------------
    def schedule_diagnosis(self):
        """При DOWN просим трассировку (если включено и есть root)."""
        self._diag_due = True

    def maybe_diagnose(self):
        if P is None:
            return
        due = getattr(self, "_diag_due", False)
        now = time.monotonic()
        # периодический режим (--diag-every) или внеплановый при DOWN
        if self._next_diag is None and not due:
            return
        if self._next_diag is not None and not due and now < self._next_diag:
            return
        self._diag_due = False
        self._next_diag = now + self.diag_every
        host = self.cfg.host
        if not host:
            return
        hops, err = P.traceroute(host, max_hops=12, timeout=1.5, queries_per_hop=2)
        if err == "raw_not_allowed":
            self.bus.emit("INFO", self.cfg.name, "diagnosis_skip",
                          "traceroute требует root (SOCK_RAW) — пропускаю",
                          rate_limit=300)
            return
        if err:
            self.bus.emit("WARN", self.cfg.name, "diagnosis_fail",
                          f"traceroute не удался: {err}", rate_limit=60)
            return
        # найти последний отвечающий хоп и где обрывается
        last_ok_hop = None
        blackholes = []
        for h in hops:
            if h["replies"]:
                last_ok_hop = h
            else:
                blackholes.append(h["hop"])
        path = " -> ".join(f"{h['hop']}:{(h['addrs'] or ['*'])[0]}({h['avg_ms']}ms)"
                           for h in hops[-6:] if h["replies"]) or "?"
        where = ""
        if blackholes:
            where = f" | чёрная дыра с хопа {blackholes[0]}"
        final = hops[-1]
        reached = bool(final["replies"]) and final["addrs"] and final["addrs"][0] in (
            P.resolve(host)[0] or [])
        msg = (f"traceroute {host}: {'дошёл' if reached else 'ОБРЫВ'} "
               f"({len(hops)} хопов){where} | путь: {path}")
        self.bus.emit("INFO" if reached else "WARN", self.cfg.name, "diagnosis", msg,
                      {"hops": hops, "reached": reached}, rate_limit=30)

    # --- оценка результата -----------------------------------------------------
    ERR_LABELS = {
        "nxdomain": "DNS: домен НЕ СУЩЕСТВУЕТ (NXDOMAIN)",
        "servfail": "DNS: сервер вернул SERVFAIL",
        "no_data": "DNS: NOERROR без записи (NODATA)",
        "dns_nxdomain": "DNS: домен НЕ СУЩЕСТВУЕТ (NXDOMAIN)",
        "dns_servfail": "DNS: сервер вернул SERVFAIL",
        "dns_no_data": "DNS: нет записи (NODATA)",
        "dns_timeout": "DNS: запрос к серверу — ТАЙМАУТ (сервер молчит)",
        "dns_unreachable": "DNS: сервер недоступен",
        "dns_failure": "DNS: ошибка резолвинга",
        "timeout": "TCP-соединение — ТАЙМАУТ (хост молчит)",
        "connect_timeout": "TCP-соединение — ТАЙМАУТ (хост молчит)",
        "refused": "ПОРТ ЗАКРЫТ (connection refused)",
        "connection_refused": "ПОРТ ЗАКРЫТ (connection refused)",
        "net_unreach": "СЕТЬ НЕДОСТУПНА (network/host unreachable)",
        "reset": "СБРОС СОЕДИНЕНИЯ (RST mid-connect)",
        "perm": "запрещено локальной политикой (EPERM)",
        "cert_expired": "TLS: СЕРТИФИКАТ ПРОСРОЧЕН",
        "cert_cn_mismatch": "TLS: сертификат НЕ НА ЭТОТ ХОСТ (hostname mismatch)",
        "cert_verify": "TLS: сертификат не прошёл проверку",
        "tls_handshake": "TLS: HANDSHAKE FAILED (несовместимые версии/шифры или блок посредником)",
        "tls_error": "TLS: ошибка протокола",
        "http_5xx": "HTTP 5xx — серверная ошибка",
        "unexpected_status": "HTTP: неожиданный статус ответа",
        "udp_no_reply": "UDP: нет ответа (обычно тихо дропается фаерволом)",
        "send_failed": "UDP: не удалось отправить",
        "no_icmp_reply": "ICMP: нет ответа",
        "unreachable": "хост недоступен",
    }

    def evaluate(self, rtt: Optional[float], err: Optional[str]):
        cfg, st = self.cfg, self.stats
        hard_fail = rtt is None
        st.add(rtt if not hard_fail else None)

        # --- событийные детекты по типу ошибки (с анти-спамом)
        if err:
            base_kind = err.split(":")[0].split("_")[0] if ":" in err else err
            kind = err if err in self.ERR_LABELS else (
                "dns_failure" if err.startswith("dns_error") else
                "timeout" if err == "connect_timeout" else
                "refused" if err == "connection_refused" else
                "net_unreach" if err.startswith("net_error") else err)
            label = self.ERR_LABELS.get(kind, err)
            crit_kinds = {"nxdomain", "servfail", "dns_failure", "dns_nxdomain",
                          "dns_servfail", "dns_timeout", "dns_unreachable",
                          "cert_expired", "cert_cn_mismatch", "tls_handshake"}
            level = "CRIT" if kind in crit_kinds else "WARN"
            # DNS/TLS-ошибки стабильны — не долбим каждые 5 секунд подряд
            if kind not in self._warned_kinds or self.state == "UP":
                if kind not in self._warned_kinds:
                    self.bus.emit(level, cfg.name, kind, label, rate_limit=60)
                    self._warned_kinds.add(kind)
        else:
            self._warned_kinds.clear()

        # --- connection_refused: ртт измерена, хост жив — DEGRADED, не DOWN
        if err in ("refused", "connection_refused", "udp_no_reply"):
            new = "DEGRADED"
        elif hard_fail and st.consec_fails < cfg.fails_to_down:
            new = self.state if self.state in ("UP", "DEGRADED") else "UNKNOWN"
        elif hard_fail:
            new = "DOWN"
        elif rtt is not None and rtt > cfg.latency_warn_ms:
            new = "DEGRADED"
        else:
            new = "UP"

        # --- EWMA-аномалии (v2): SPIKE/DROP относительно собственной базы нормы
        if rtt is not None and self.baseline is not None:
            anom, why = self.baseline.update(rtt)
            if anom:
                self.bus.emit("WARN", cfg.name, "latency_anomaly",
                              f"АНОМАЛИЯ ЗАДЕРЖКИ — {why}", {"rtt_ms": round(rtt, 1)})
                if new == "UP":
                    new = "DEGRADED"

        # --- джиттер и потери в окне (v2)
        if not hard_fail:
            if st.jitter is not None and st.jitter > cfg.jitter_warn_ms and \
                    "jitter_high" not in self._warned_kinds:
                self._warned_kinds.add("jitter_high")
                self.bus.emit("WARN", cfg.name, "jitter_high",
                              f"ВЫСОКИЙ ДЖИТТЕР: {st.jitter:.0f}ms > порога {cfg.jitter_warn_ms:.0f}ms "
                              f"(несетевой шум/перегрузка канала)",
                              {"jitter_ms": round(st.jitter, 1)})
            if st.win_loss_pct > cfg.loss_warn_pct and len(st.fail_flags) >= 6 and \
                    "packet_loss" not in self._warned_kinds:
                self._warned_kinds.add("packet_loss")
                self.bus.emit("WARN", cfg.name, "packet_loss",
                              f"ПОТЕРИ ПАКЕТОВ: {st.win_loss_pct:.0f}% за последние "
                              f"{len(st.fail_flags)} проб (> {cfg.loss_warn_pct:.0f}%)",
                              {"win_loss_pct": round(st.win_loss_pct, 1)})
            if st.win_loss_pct <= cfg.loss_warn_pct / 2:
                self._warned_kinds.discard("packet_loss")
                self._warned_kinds.discard("jitter_high")

        if new != self._reported_state:
            snap = st.snapshot()
            if new == "DOWN":
                self.bus.emit("CRIT", cfg.name, "down",
                              f"UNREACHABLE ({err or 'no reply'}) | "
                              f"consec_fails={snap['consec_fails']} loss={snap['win_loss_pct']}%",
                              {"error": err, **snap})
                self.schedule_diagnosis()
            elif new == "DEGRADED":
                why = err or f"rtt={rtt:.0f}ms > {cfg.latency_warn_ms:.0f}ms"
                self.bus.emit("WARN", cfg.name, "degraded", f"SLOW/PARTIAL: {why}",
                              {"rtt_ms": round(rtt, 1) if rtt else None, **snap})
            elif self._reported_state in ("DOWN", "DEGRADED") and new == "UP":
                self.bus.emit("INFO", cfg.name, "recovered",
                              f"RECOVERED: rtt={rtt:.0f}ms (probes total={st.total})",
                              {"rtt_ms": round(rtt, 1), **snap})
            self._reported_state = new
        self.state = new
        if self.state == "DOWN":
            self.schedule_diagnosis()

    # --- цикл ------------------------------------------------------------------
    def run(self):
        cfg = self.cfg
        next_t = time.monotonic()
        while not self.stop_evt.is_set():
            try:
                rtt, err = self.probe_once()
            except Exception as e:
                rtt, err = None, f"probe_exception: {type(e).__name__}: {e}"
            self.evaluate(rtt, err)
            if getattr(self, "_diag_due", False):
                try:
                    self.maybe_diagnose()
                except Exception as e:
                    self.bus.emit("WARN", cfg.name, "diagnosis_error",
                                  f"diagnosis failed: {type(e).__name__}: {e}")
            if self.csv_writer:
                row = {"ts": now_iso(), "target": cfg.name, "state": self.state,
                       "rtt_ms": round(rtt, 1) if rtt is not None else "",
                       "error": err or "", **self.stats.snapshot()}
                if self.csv_lock:
                    with self.csv_lock:
                        self.csv_writer.writerow(row)
                else:
                    self.csv_writer.writerow(row)
            next_t += cfg.interval
            delay = next_t - time.monotonic()
            if delay < 0:
                next_t = time.monotonic()
                delay = 0
            self.stop_evt.wait(delay)

    def line(self) -> str:
        st = self.stats
        col = {"UP": ok, "DOWN": bad, "DEGRADED": warn}.get(self.state, dim)
        icon = {
            "UP": " ● ", "DOWN": " ● ", "DEGRADED": " ● "}.get(self.state, " ○ ")
        rtt = f"{st.last_ok:.0f}ms" if st.last_ok is not None else "-"
        jit = f"{st.jitter:.0f}ms" if st.jitter is not None else "-"
        p95 = st.percentile(95)
        probe_kind = self.cfg.mode if self.cfg.mode != "auto" else (
            "http" if st and self.cfg.url else ("tcp" if self.cfg.port else "icmp"))
        base = (f"{col(icon)}{bold(self.cfg.name.ljust(30))} {col(self.state.ljust(9))} "
                f"[{probe_kind:>5}] rtt={rtt:>7} avg={st.avg_rtt:>6.0f}ms "
                f"jit={jit:>6} loss={st.win_loss_pct:>5.1f}% "
                f"({st.failures}/{st.total})")
        extras = []
        if p95:
            extras.append(f"p95={p95:.0f}ms")
        if self.baseline and self.baseline.ready:
            extras.append(f"base={self.baseline.mean:.0f}ms")
        if self.last_detail:
            extras.append(self.last_detail[:40])
        return base + (dim("  " + " ".join(extras)) if extras else "")


# -----------------------------------------------------------------------------
# Дашборд
# -----------------------------------------------------------------------------

def dashboard_loop(probers: List[Prober], routes: RouteMonitor,
                   stop: threading.Event, period: float):
    while not stop.wait(period):
        lines = [bold(cyan(f"── netwatch · {now_iso()} ")) +
                 dim(" (Ctrl+C — выход)")]
        lines += [p.line() for p in probers]
        rs = routes.last_state
        if rs is not None:
            lines.append(dim(f"route: default via {rs.get('gw')} dev {rs.get('iface')}")
                         if rs.get("default") else bad("route: NO DEFAULT ROUTE!"))
        body = "\n".join(lines) + "\n"
        if USE_COLOR:
            sys.stdout.write("\033[H\033[2J" + body)
        else:
            sys.stdout.write(body + "\n")
        sys.stdout.flush()


# -----------------------------------------------------------------------------
# Конфиг (TOML-подобный, свой мини-парсер)
# -----------------------------------------------------------------------------

def load_config(path: Path, defaults: TargetConfig) -> List[TargetConfig]:
    targets: List[TargetConfig] = []
    section = None
    section_name = None
    kv: dict = {}

    def flush():
        nonlocal kv
        if section != "target" or not kv:
            kv = {}
            return
        # форма target = "tls:host:443" | "https://..." | "host:443"
        if kv.get("target"):
            sub = parse_target(kv["target"], defaults)
            if kv.get("name"):
                sub.name = kv["name"]
            elif section_name:
                sub.name = section_name
            for fnum in ("interval", "timeout", "latency_warn_ms",
                         "jitter_warn_ms", "loss_warn_pct"):
                if kv.get(fnum):
                    setattr(sub, fnum, float(kv[fnum]))
            if kv.get("fails_to_down"):
                sub.fails_to_down = int(kv["fails_to_down"])
            if kv.get("dns_server"):
                sub.dns_server = kv["dns_server"]
            if kv.get("expect_status"):
                sub.expect_status = int(kv["expect_status"])
            if kv.get("mode"):
                sub.mode = kv["mode"]
            if kv.get("baseline") is not None:
                sub.baseline = kv["baseline"].lower() not in ("false", "0", "no", "off")
            if kv.get("verify_tls") is not None:
                sub.verify_tls = kv["verify_tls"].lower() not in ("false", "0", "no", "off")
            targets.append(sub)
            kv = {}
            return
        # классическая форма host=/url=
        if kv.get("host") or kv.get("url"):
            t = TargetConfig(name=(kv.get("name") or section_name
                                   or kv.get("host") or kv.get("url")))
            t.host = kv.get("host")
            t.url = kv.get("url")
            t.port = int(kv["port"]) if kv.get("port") else None
            if t.url and not kv.get("mode"):
                pr = urllib.parse.urlparse(t.url)
                t.host = t.host or pr.hostname
                if pr.scheme in ("http", "https"):
                    t.mode = pr.scheme
                    t.port = t.port or (443 if pr.scheme == "https" else 80)
            for fnum in ("interval", "timeout", "latency_warn_ms"):
                if kv.get(fnum):
                    setattr(t, fnum, float(kv[fnum]))
            if kv.get("fails_to_down"):
                t.fails_to_down = int(kv["fails_to_down"])
            for fnum in ("jitter_warn_ms", "loss_warn_pct"):
                if kv.get(fnum):
                    setattr(t, fnum, float(kv[fnum]))
            if kv.get("mode"):
                t.mode = kv["mode"]
            if kv.get("expect_status"):
                t.expect_status = int(kv["expect_status"])
            if kv.get("dns_server"):
                t.dns_server = kv["dns_server"]
            if kv.get("baseline") is not None:
                t.baseline = kv["baseline"].lower() not in ("false", "0", "no", "off")
            if kv.get("verify_tls") is not None:
                t.verify_tls = kv["verify_tls"].lower() not in ("false", "0", "no", "off")
            targets.append(t)
        kv = {}

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r'\[\[?\s*(\w+)(?:\s+"([^"]*)")?\s*\]?\]\s*$', line)  # [x] / [[x]] / [x "имя"]
        if m:
            flush()
            section, section_name = m.group(1), m.group(2)
            continue
        m = re.match(r'\[[ \t]*(\w+)[ \t]*\][ \t]*$', line)   # классический INI-заголовок
        if m:
            flush()
            section, section_name = m.group(1), None
            continue
        m = re.match(r'^(\w+)[ \t]*=[ \t]*"([^"]*)"[ \t]*$', line)   # toml: key = "value"
        if not m:
            m = re.match(r'^(\w+)[ \t]*=[ \t]*([^;]+?)[ \t]*$', line)   # ini/toml: key = value (без кавычек)
        if m and section == "target":
            kv[m.group(1)] = m.group(2)
        elif m and section == "defaults" and m.group(1) in (
                "interval", "timeout", "latency_warn_ms", "fails_to_down",
                "jitter_warn_ms", "loss_warn_pct"):
            v = m.group(2)
            if m.group(1) == "fails_to_down":
                setattr(defaults, m.group(1), int(v))
            else:
                setattr(defaults, m.group(1), float(v))
    flush()
    return targets


# -----------------------------------------------------------------------------
# Отчёт по JSONL-логу
# -----------------------------------------------------------------------------

def report(log_path: Path):
    per = defaultdict(lambda: defaultdict(int))
    levels = defaultdict(lambda: defaultdict(int))
    tmin = tmax = None
    for line in log_path.read_text(encoding="utf-8").splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = ev.get("target", "?")
        per[t][ev.get("kind", "?")] += 1
        levels[t][ev.get("level", "?")] += 1
        ts = ev.get("ts")
        if ts:
            tmin = min(tmin, ts) if tmin else ts
            tmax = max(tmax, ts) if tmax else ts
    print(bold(f"Отчёт: {log_path}"))
    print(dim(f"период: {tmin} .. {tmax}") + "\n")
    crit_kinds = {"down", "dns_failure", "route_lost", "nxdomain", "servfail",
                  "dns_nxdomain", "dns_servfail", "dns_timeout", "dns_unreachable",
                  "cert_expired", "cert_cn_mismatch", "tls_handshake", "iface_down",
                  "no_internet", "timeout", "refused", "net_unreach", "reset",
                  "http_5xx", "unexpected_status", "cert_expiring"}
    warn_kinds = {"degraded", "route_switch", "icmp_blocked", "latency_anomaly",
                  "jitter_high", "packet_loss", "clock_skew", "captive_portal",
                  "dns_config_changed", "diagnosis", "diagnosis_fail"}
    for tgt in sorted(per):
        total_ev = sum(per[tgt].values())
        head = f"{bold(tgt)}  ({total_ev} событий)"
        print(head)
        for kind, n in sorted(per[tgt].items(), key=lambda x: -x[1]):
            bar = "█" * min(40, n)
            color = bad(bar) if kind in crit_kinds else warn(bar) if kind in warn_kinds else ok(bar)
            print(f"   {kind:<16} {n:>4}  {color}")
        print()


# -----------------------------------------------------------------------------
# Разовая диагностика окружения (--detect)
# -----------------------------------------------------------------------------

def detect_env(timeout: float = 2.0) -> int:
    print(bold("netwatch --detect: диагностика сетевого окружения"))
    print("-" * 60)
    if P is None:
        print(bad("nw_probes.py не найден — расширенная диагностика недоступна"))
        return 2

    ips, err = P.resolve("example.com")
    print(("  " + ok(f"DNS системный: example.com -> {', '.join(ips[:2])}"))
          if not err else ("  " + bad(f"DNS системный: ОШИБКА ({err})")))

    servers = read_resolv_conf()
    print(dim(f"  resolv.conf nameservers: {', '.join(servers) if servers else 'нет данных'}"))
    for srv in servers[:2] + ([s for s in ["1.1.1.1"] if s not in servers][:1]):
        lat, ans, derr, rcode = P.dns_query("example.com", srv, timeout=min(3.0, timeout + 1))
        if derr:
            print(bad(f"  DNS-сервер {srv}: {derr}"))
        else:
            print(ok(f"  DNS-сервер {srv}: {lat:.0f}ms, rcode={rcode}, answer={ans[0] if ans else '-'}"))

    has, how = P.connectivity_check(timeout=timeout + 1)
    print((ok("  Интернет-доступность: ЕСТЬ (") + dim(how) + ok(")")) if has
          else (bad("  Интернет-доступность: НЕТ (") + dim(how) + bad(")")))

    caught, info = P.captive_portal_detect(timeout=timeout + 1)
    if caught:
        print(warn(f"  Captive portal: ОБНАРУЖЕН — hotspot-DNS отвечает: {info}"))
    else:
        print(ok(f"  Captive portal: не обнаружен ({info})"))

    reps, err, got = P.raw_icmp_ping("1.1.1.1", count=2, timeout=timeout)
    if err == "raw_not_allowed":
        print(dim("  Raw ICMP: недоступен без root — ping через системный /bin/ping"))
    elif got:
        avg = sum(r for _, r in reps) / len(reps)
        print(ok(f"  Raw ICMP на 1.1.1.1: {got}/2 ответов, avg {avg:.1f}ms"))
    else:
        print(warn(f"  Raw ICMP на 1.1.1.1: нет ответов (err={err})"))

    mtu, merr = P.mtu_discovery_scan("1.1.1.1", timeout=timeout)
    if merr in (None,) and mtu:
        print(ok(f"  Path MTU до 1.1.1.1: ~{mtu}"))
    elif merr and str(merr).startswith("frag_needed_at"):
        print(warn(f"  Path MTU: фрагментация нужна — {merr}"))
    else:
        print(dim(f"  Path MTU: не определён ({merr})"))

    hops, terr = P.traceroute("one.one.one.one", max_hops=15, timeout=1.5, queries_per_hop=2)
    if terr:
        print(dim(f"  Traceroute: {terr}"))
    else:
        print(ok(f"  Traceroute one.one.one.one: {len(hops)} хопов, последний отвечающий: "
                 f"{hops[-1]['addrs'][0] if hops and hops[-1]['addrs'] else '?'}"))
        for h in hops:
            mark = ok("*") if h["replies"] else bad("*")
            addr = ", ".join(h["addrs"]) or " *"
            ms = f"{h['avg_ms']}ms" if h["avg_ms"] is not None else "-"
            print(dim(f"    {h['hop']:>2}. {mark} {addr:<40} {ms}"))
    return 0


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# netfix — полная очистка сетевого стека (Windows) / эквиваленты (Linux/macOS)
#   netsh int ip reset ; netsh winsock reset ; ipconfig /flushdns ; ipconfig /renew
# -----------------------------------------------------------------------------

WIN_RESET_STEPS = [
    ("ipconfig /flushdns", ["ipconfig", "/flushdns"], False),
    ("netsh int ip reset", ["netsh", "int", "ip", "reset"], True),
    ("netsh winsock reset", ["netsh", "winsock", "reset"], True),
    ("ipconfig /release",  ["ipconfig", "/release"], True),
    ("ipconfig /renew",    ["ipconfig", "/renew"], True),
]


def _is_admin_windows() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        # грубая страховка, если ctypes по какой-то причине недоступен
        try:
            out = subprocess.run(["net", "session"], capture_output=True).returncode
            return out == 0
        except Exception:
            return False


def run_step(title: str, cmd, shell: bool, dry_run: bool) -> Tuple[int, str]:
    """Выполняет один шаг очистки. Возвращает (rc, текст вывода)."""
    printable = title if not isinstance(cmd, list) else " ".join(cmd)
    if dry_run:
        print("  " + dim(f"[dry-run] {printable}"))
        return 0, ""
    try:
        proc = subprocess.run(cmd, shell=shell, capture_output=True, text=True,
                              timeout=60, encoding="utf-8", errors="replace")
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        rc = proc.returncode
    except FileNotFoundError:
        out, rc = "команда не найдена", 127
    except subprocess.TimeoutExpired:
        out, rc = "таймаут 60с", 124
    except Exception as e:                       # noqa: BLE001
        out, rc = f"ошибка запуска: {e}", 1
    status = ok("OK ") if rc == 0 else bad(f"rc={rc}")
    print(f"  {status} {bold(printable)}")
    for line in out.splitlines():
        print("       " + dim(line))
    return rc, out


def netfix_win(dry_run: bool, reboot: bool) -> int:
    admin = _is_admin_windows()
    print(bold("netfix: полная очистка сетевого стека (Windows)"))
    print(dim("  шаги: flushdns → netsh int ip reset → netsh winsock reset → "
              "ipconfig /release → /renew"))
    if not admin and not dry_run:
        print(warn("  ⚠ Нет прав администратора: netsh int ip reset / winsock reset / "
                   "ipconfig /renew\n    требуют запуска от администратора "
                   "(«Запуск от имени администратора»)."))
    failed = []
    for title, cmd, needs_admin in WIN_RESET_STEPS:
        if needs_admin and not admin and not dry_run:
            print("  " + warn(f"skip {title} — нужны права администратора"))
            failed.append(title)
            continue
        rc, _ = run_step(title, cmd, False, dry_run)
        if rc != 0:
            failed.append(title)
    print()
    if failed:
        print(warn(f"Итог: выполнено с проблемами: {', '.join(failed)}"))
    else:
        print(ok("Все шаги выполнены."))
        if not dry_run:
            print(dim("Рекомендуется перезагрузка (winsock/стек применятся после неё), "
                      "затем проверка: netwatch --detect"))
    if reboot and not dry_run and admin:
        print(warn("Перезагрузка через 15 секунд (shutdown /r /t 15)… Ctrl+C чтобы отменить.")
              )
        try:
            time.sleep(15)
            subprocess.run(["shutdown", "/r", "/t", "0"])
        except KeyboardInterrupt:
            print("\n" + dim("Перезагрузка отменена."))
    return 1 if failed else 0


def netfix_unix(dry_run: bool) -> int:
    """Эквивалент «полной очистки» для Linux/macOS: сброс DNS-кэша, DHCP-обновление,
    чистка ARP/neighbour кэшей, soft-flush маршрутов и очищаемых sysctl."""
    system = platform.system()
    print(bold(f"netfix: очистка сетевого стека ({system})"))
    print(dim("  Windows-аналоги: flushdns→DNS-кэш, ipconfig /renew→DHCP, "
              "winsock/int ip reset→sysctl/очереди"))
    failed = []

    euid = os.geteuid() if not dry_run else 0   # dry-run не требует прав
    def sh(title: str, script: str, needs_root: bool = True):
        if dry_run:
            print("  " + dim(f"[dry-run] {title}: {script}"))
            return 0
        if needs_root and euid != 0:
            print("  " + warn(f"skip {title} — нужен root (sudo)"))
            failed.append(title)
            return 1
        proc = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
        rc = proc.returncode
        status = ok("OK ") if rc == 0 else bad(f"rc={rc}")
        print(f"  {status} {bold(title)}")
        for line in ((proc.stdout or "") + (proc.stderr or "")).splitlines():
            print("       " + dim(line))
        if rc != 0:
            failed.append(title)
        return rc

    # 1. DNS-кэш (аналог ipconfig /flushdns)
    if shutil.which("resolvectl"):
        sh("flush DNS cache (systemd-resolved)", "resolvectl flush-caches", False)
    elif shutil.which("systemd-resolve"):
        sh("flush DNS cache (systemd-resolve)", "systemd-resolve --flush-caches", False)
    elif shutil.which("dnscacheutil"):           # macOS
        sh("flush DNS cache (mDNSResponder)", "dscacheutil -flushcache; "
                                              "killall -HUP mDNSResponder", False)
    else:
        print("  " + warn("DNS-кэш: ни resolvectl, ни dscacheutil не найдены — "
                          "пропускаю (вероятно, кэша нет)"))

    # 2. ARP / neighbour-кэш
    if system == "Darwin":
        sh("flush ARP cache", "arp -ad", True)
    else:
        sh("flush ARP/neighbour cache", "ip -s neigh flush all", True)

    # 3. DHCP release/renew (аналог ipconfig /release + /renew)
    iface = None
    try:
        route = subprocess.run(["ip", "route", "show", "default"],
                               capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"\bdev\s+(\S+)", route)
        if m:
            iface = m.group(1)
    except Exception:
        pass
    if system == "Darwin":
        iface = iface or "en0"
        sh(f"DHCP renew on {iface}",
           f"ipconfig set {iface} BOOTP; ipconfig getifaddr {iface}", True)
    elif iface:
        nmcli = shutil.which("nmcli")
        if nmcli:
            sh(f"DHCP renew via NetworkManager ({iface})",
               f"nmcli device reapply {iface} || nmcli device connect {iface}", True)
        elif shutil.which("dhclient"):
            sh(f"DHCP release+renew on {iface} (dhclient)",
               f"dhclient -r {iface}; dhclient {iface}", True)
        else:
            sh(f"link bounce {iface} (fallback)",
               f"ip link set {iface} down && sleep 1 && ip link set {iface} up", True)
    else:
        print("  " + warn("не удалось определить default-интерфейс — DHCP renew пропускаю"))

    # 4. Сброс «winsock-подобного»: очищаемые sysctl/очереди/TW-сокеты
    if system != "Darwin":
        sh("drop packet queues & conntrack",
           "tc qdisc del dev lo root 2>/dev/null; "
           "conntrack -F 2>/dev/null || true", True)
        sh("purge TIME_WAIT-ish sockets info & reset routing caches",
           "ip route flush cache", True)
    print()
    if failed:
        print(warn(f"выполнено с пропусками/ошибками: {', '.join(failed)}"))
        return 1
    print(ok("Очистка выполнена. Проверка: python3 netwatch.py --detect"))
    return 0


def cmd_netfix(args) -> int:
    system = platform.system()
    if args.dry_run:
        print(dim("[dry-run] ничего не будет изменено\n"))
    if system == "Windows":
        return netfix_win(args.dry_run, args.reboot)
    return netfix_unix(args.dry_run)


def cmd_accel(args) -> int:
    """Подкоманда accel: собрать/проверить C-ядро nwaccel."""
    if A is None:
        print(bad("nwaccel.py потерян рядом с netwatch.py"), file=sys.stderr)
        return 2
    st = A.engine_status(auto_build=args.build)
    print(bold("C-ядро netwatch (nwaccel):"))
    print(f"  платформа поддерживается : {st['platform_ok']}")
    print(f"  бинарь                   : {st['binary'] or '-'}")
    print(f"  статус                   : {st['status']}"
          + (" (собран сейчас)" if st["built_now"] else ""))
    print(f"  raw-ICMP доступен        : {st['icmp_usable']} "
          "(нужен root/CAP_NET_RAW)")
    if st["status"] != "ready":
        print(dim("  сборка: python3 netwatch.py accel --build   "
                  "(или gcc -O2 -pthread -o nwaccel nwaccel.c)"))
        return 1
    if st["icmp_usable"]:
        d = A.c_ping("127.0.0.1", count=20, interval_ms=5)
        if d:
            print(ok(f"  ping self-test: sent={d['sent']} recv={d['received']} "
                     f"avg={d['avg_ms']:.3f}ms mdev={d['mdev_ms']:.3f}ms"))
    dns = A.c_dns_resolve_many(["example.com", "one.one.one.one",
                                "invalid-host-nwtest.invalid"])
    if dns:
        bad_hosts = [h for h, r in dns.items() if not r.get("ok")]
        print(ok(f"  dns self-test: {len(dns)} хостов за один вызов, "
                 f"фейлы как ожидалось: {bad_hosts}"))
    return 0


# ---------------------------------------------------------------- selftest --
def cmd_selftest(args) -> int:
    """Оффлайновые unit-тесты парсеров/статистики/интеграции C-ядра.

    Сеть не требуется (кроме пары быстрых DNS/TCP-проб на localhost).
    Возвращает число проваленных тестов — build.bat использует это как gate.
    """
    fails = []

    def check(name, fn):
        try:
            fn()
            print(ok(f"  [PASS] {name}"))
        except Exception as e:
            fails.append(name)
            print(bad(f"  [FAIL] {name}: {type(e).__name__}: {e}"))

    dflt = TargetConfig(name="")

    # --- парсер целей ---
    def t_parse_ip():
        t = parse_target("8.8.8.8", dflt)
        assert t.host == "8.8.8.8" and t.mode == "auto", (t.host, t.mode)

    def t_parse_hostport():
        t = parse_target("db:localhost:5432", dflt)
        assert t.name == "db" and t.host == "localhost" and t.port == 5432, vars(t)

    def t_parse_url():
        t = parse_target("https://example.com/health", dflt)
        assert t.mode == "https" and t.host == "example.com", vars(t)

    def t_parse_mode_tls():
        t = parse_target("tls:one.one.one.one:443", dflt)
        assert t.mode == "tls" and t.host == "one.one.one.one" and t.port == 443, vars(t)

    def t_parse_dns_at_server():
        t = parse_target("dns:example.com@9.9.9.9", dflt)
        assert t.mode == "dns" and t.dns_server == "9.9.9.9", vars(t)

    # --- Stats: скользящее окно, потери, джиттер, перцентили ---
    def t_stats():
        s = Stats(window=10)
        for ms in [10, 12, 11, 50, None, 13, 14, None, 15]:
            s.add(ms)
        snap = s.snapshot()
        assert snap["total"] == 9 and snap["failures"] == 2, snap
        assert abs(s.win_loss_pct - 100.0 * 2 / 9) < 0.1, s.win_loss_pct
        assert s.avg_rtt > 0 and s.percentile(95) is not None, s.rtts
        assert s.jitter is not None, "джиттер не посчитан"

    def t_stats_consec():
        s = Stats(window=5)
        s.add(10); s.add(None); s.add(None)
        assert s.consec_fails == 2, s.consec_fails
        s.add(11)
        assert s.consec_fails == 0, s.consec_fails

    # --- Baseline EWMA ---
    def t_baseline():
        b = Baseline(alpha=0.25, k=4.0, min_abs_ms=50.0)
        for _ in range(30):
            anomaly, _desc = b.update(100.0)
        assert b.ready and b.mean is not None and 90 < b.mean < 110, b.mean
        anomaly, desc = b.update(900.0)
        assert anomaly and "SPIKE" in desc, (anomaly, desc)
        anomaly, _ = b.update(102.0)
        assert not anomaly, "норма не должна быть аномалией"

    # --- конфиг INI + TOML-пример ---
    def t_cfg_ini():
        with open("/tmp/nw-selftest.ini", "w") as f:
            f.write("[defaults]\ninterval = 7\nlatency_warn_ms = 300\n\n"
                    "[target \"gw\"]\ntarget = 192.168.1.1\n\n"
                    "[target \"db\"]\nhost = localhost\nport = 5432\n")
        ts = load_config(Path("/tmp/nw-selftest.ini"), TargetConfig(name=""))
        assert len(ts) == 2, ts
        by = {t.name: t for t in ts}
        assert by["db"].port == 5432 and by["gw"].host == "192.168.1.1", by
        assert by["gw"].interval == 7.0, "defaults не применились"

    def t_cfg_toml():
        src = Path(__file__).with_name("netwatch.toml")
        if not src.exists():
            return
        ts = load_config(src, TargetConfig(name=""))
        assert len(ts) == 4, [t.name for t in ts]
        by = {t.name: t for t in ts}
        assert by["my-site"].mode == "https" and by["postgres"].port == 5432, by

    # --- репортер по синтетическому логу ---
    def t_report():
        p = Path("/tmp/nw-selftest.jsonl")
        p.write_text(
            json.dumps({"ts": "2026-01-01T00:00:00+00", "target": "a",
                        "level": "WARN", "event": "latency_spike"}) + "\n" +
            json.dumps({"ts": "2026-01-01T00:00:05+00", "target": "a",
                        "level": "CRIT", "event": "down"}) + "\n" +
            "{broken line}\n", encoding="utf-8")  # битая строка должна молча пропускаться
        rc = report(p)
        assert rc in (None, 0, 1), rc

    # --- netfix dry-run (ничего не выполняем) ---
    def t_fix_dryrun():
        ns = argparse.Namespace(dry_run=True, reboot=False)
        rc = cmd_netfix(ns)
        assert rc in (0, 1), rc  # dry-run не имеет права падать в стектрейс

    # --- nw_probes: DNS-пакет, TCP на закрытый порт, raw-ICMP graceful ---
    def t_probe_dns_packet():
        # проверка формата DNS-запроса (RD-бит, длина) без зависимости от сервера
        name = b"".join(bytes([len(l)]) + l.encode() for l in ("example", "com")) + b"\x00"
        hdr = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        pkt = hdr + name + struct.pack(">HH", 1, 1)
        assert pkt[2:4] == b"\x01\x00", "RD-бит должен стоять"
        assert len(pkt) == 12 + len(name) + 4

    def t_probe_tcp_refused():
        import nw_probes as NP
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        res = NP.tcp_probe("127.0.0.1", port, 1.0)
        rtt, err = res[0], res[1]
        assert err and rtt is None, (rtt, err)

    def t_probe_icmp_perm():
        import nw_probes as NP
        try:
            r = NP.raw_icmp_ping("127.0.0.1", count=1, timeout=0.5)
        except PermissionError:
            r = None
        assert r is None or isinstance(r, (tuple, dict, float)), r

    # --- C-ядро: контракт CLI + JSON через Python-обвязку ---
    def t_accel_contract():
        if A is None:
            return
        st = A.engine_status(auto_build=False)
        if st["status"] != "ready":
            print(dim("  [SKIP] nwaccel не собран (build.bat / accel --build)"))
            return
        binary = Path(st["binary"])
        for flag in ("--count", "--interval"):
            r = subprocess.run([str(binary), "ping", "127.0.0.1", flag, "1"],
                               capture_output=True, text=True, timeout=20)
            assert "unknown opt" not in (r.stderr + r.stdout), \
                f"C-ядро не понимает {flag} — бинарь устарел относительно исходников"
        dns = A.c_dns_resolve_many(["localhost", "invalid-host-nwtest.invalid"])
        if dns is not None:
            assert dns.get("localhost", {}).get("ok") is True, dns
            assert dns.get("invalid-host-nwtest.invalid", {}).get("ok") is False, dns

    print(bold("netwatch selftest:"))
    check("parse: ip", t_parse_ip)
    check("parse: alias:host:port", t_parse_hostport)
    check("parse: https url", t_parse_url)
    check("parse: tls mode", t_parse_mode_tls)
    check("parse: dns@server", t_parse_dns_at_server)
    check("stats: window/loss/jitter", t_stats)
    check("stats: consec_fails", t_stats_consec)
    check("baseline: EWMA anomaly", t_baseline)
    check("config: INI", t_cfg_ini)
    check("config: netwatch.toml", t_cfg_toml)
    check("report: jsonl (+битые строки)", t_report)
    check("fix: dry-run", t_fix_dryrun)
    check("probes: dns packet", t_probe_dns_packet)
    check("probes: tcp refused", t_probe_tcp_refused)
    check("probes: raw icmp graceful", t_probe_icmp_perm)
    check("accel: CLI contract", t_accel_contract)

    total = 16
    if fails:
        print(bad(f"\n{len(fails)}/{total} провалено: {', '.join(fails)}"))
    else:
        print(ok(f"\nВсе {total} тестов зелёные."))
    return len(fails)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netwatch", formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Монитор сетевых ошибок и проблем подключения.")
    sub = p.add_subparsers(dest="command")
    fx = sub.add_parser("fix", aliases=["netfix"],
                        help="полная очистка сетевого стека "
                             "(netsh int ip reset, netsh winsock reset, "
                             "ipconfig /flushdns, ipconfig /renew)")
    fx.add_argument("--reboot", action="store_true",
                    help="Windows: перезагрузить сразу после очистки "
                         "(winsock применяется только после reboot)")
    fx.add_argument("--dry-run", action="store_true",
                    help="показать команды, ничего не выполнять")
    fx.set_defaults(func=cmd_netfix)
    ac = sub.add_parser("accel", aliases=["ccore"],
                        help="собрать/проверить C-ядро nwaccel "
                             "(flood-ping, пакетный DNS)")
    ac.add_argument("--build", action="store_true",
                    help="скомпилировать nwaccel.c через gcc/cc (-O2 -pthread)")
    ac.set_defaults(func=cmd_accel)
    stp = sub.add_parser("selftest", aliases=["test"],
                         help="оффлайновые unit-тесты (используется build.bat)")
    stp.set_defaults(func=cmd_selftest)
    ca = p.add_argument_group("C-ядро (ускорение)")
    ca.add_argument("--c-core", action="store_true",
                    help="ICMP-пробы через C-ядро: flood-ping с mdev/p50/p95 "
                         "(нужен собранный nwaccel + root; иначе фолбэк на Python)")
    ca.add_argument("--c-build", action="store_true",
                    help="автосборка nwaccel.c при старте, если бинаря нет")
    ca.add_argument("--ping-samples", type=int, default=4, metavar="N",
                    help="ICMP-эхо на одну пробу в C-ядре [4]")
    ca.add_argument("--ping-rate-ms", type=int, default=100, metavar="MS",
                    help="интервал между эхо внутри пробы [100]")
    p.add_argument("-t", "--targets", nargs="+", metavar="SPEC",
                   help="8.8.8.8 | example.com | host:443 | https://site | alias:host:443")
    p.add_argument("-c", "--config", type=Path, help="INI/TOML-конфиг с [[target]] секциями")
    p.add_argument("-i", "--interval", type=float, default=5.0, help="период проб, сек [5]")
    p.add_argument("--timeout", type=float, default=2.0, help="таймаут пробы, сек [2]")
    p.add_argument("--warn-ms", type=float, default=250.0, help="порог DEGRADED, мс [250]")
    p.add_argument("--fails-to-down", type=int, default=2,
                   help="фейлов подряд до статуса DOWN [2]")
    p.add_argument("--log", type=Path, default=Path("netwatch-events.jsonl"),
                   help="JSONL лог событий [netwatch-events.jsonl]")
    p.add_argument("--no-log", action="store_true", help="не писать лог")
    p.add_argument("--csv", type=Path, help="CSV всех проб")
    p.add_argument("--dashboard", action="store_true", help="live-дашборд вместо потока событий")
    p.add_argument("--period", type=float, default=2.0, help="обновление дашборда, сек [2]")
    p.add_argument("--tg-token", help="Telegram bot token")
    p.add_argument("--tg-chat", help="Telegram chat id")
    p.add_argument("--webhook", help="generic webhook URL (JSON POST)")
    p.add_argument("--alert-on", default="CRIT", choices=["WARN", "CRIT"],
                   help="мин. уровень внешних алертов [CRIT]")
    g = p.add_argument_group("v2: расширенный детект")
    g.add_argument("--deep", action="store_true",
                   help="системные проверки: линк интерфейсов, интернет-доступность, "
                        "captive portal, смена resolv.conf")
    g.add_argument("--no-baseline", action="store_true",
                   help="выключить EWMA-базу нормы (детект latency_anomaly)")
    g.add_argument("--jitter-warn-ms", type=float, default=80.0,
                   help="порог тревоги по джиттеру [80]")
    g.add_argument("--loss-warn-pct", type=float, default=20.0,
                   help="порог %% потерь в окне для packet_loss [20]")
    g.add_argument("--diag-every", type=float, default=0.0, metavar="SEC",
                   help="периодический traceroute (нужен root), 0=только при DOWN")
    g.add_argument("--detect", action="store_true",
                   help="разовая диагностика окружения (raw-ICMP/traceroute/portal/"
                        "интернет/DNS-латентность) и выход")
    p.add_argument("--report", type=Path, metavar="JSONL",
                   help="показать отчёт по логу и выйти")
    p.add_argument("--duration", type=float, help="автоостановка через N секунд")
    return p


CSV_FIELDS = ["ts", "target", "state", "rtt_ms", "error", "total", "failures",
              "loss_pct", "win_loss_pct", "avg_ms", "last_ms", "max_ms",
              "p95_ms", "jitter_ms", "consec_fails"]


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    # подкоманда netwatch fix — полная очистка сетевого стека
    if getattr(args, "command", None):
        return args.func(args)

    # --- C-ядро: включаем по флагу, при --c-build собираем на лету ---
    if A is not None and (args.c_core or args.c_build):
        st = A.engine_status(auto_build=args.c_build or args.c_core)
        if st["status"] == "ready":
            ACCEL["on"] = True
            ACCEL["interval_ms"] = max(10, args.ping_rate_ms)
            ACCEL["sockets"] = 2 if args.ping_samples > 8 else 1
            os.environ["NW_C_PING_N"] = str(max(2, args.ping_samples))
            msg = f"C-ядро: {st['binary']}"
            if st["built_now"]:
                msg += " (собрано сейчас)"
            if not st["icmp_usable"]:
                msg += (" — ВНИМАНИЕ: raw-ICMP недоступен (нужен root), "
                        "работает фолбэк на Python-ping")
            print(dim(msg))
        else:
            print(warn("C-ядро недоступно: нет бинаря/компилятора — "
                       "работаю на Python"))

    if args.detect:
        return detect_env(args.timeout)

    if args.report:
        if not args.report.exists():
            print(bad(f"лог не найден: {args.report}"), file=sys.stderr)
            return 2
        report(args.report)
        return 0

    defaults = TargetConfig(name="_", interval=args.interval, timeout=args.timeout,
                            latency_warn_ms=args.warn_ms,
                            fails_to_down=args.fails_to_down,
                            jitter_warn_ms=args.jitter_warn_ms,
                            loss_warn_pct=args.loss_warn_pct,
                            baseline=not args.no_baseline)
    targets: List[TargetConfig] = []
    if args.targets:
        targets.extend(parse_target(s, defaults) for s in args.targets)
    if args.config:
        targets.extend(load_config(args.config, defaults))
    if not targets:
        print(dim("Цели не заданы — беру стандартный набор: 1.1.1.1, 8.8.8.8, "
                  "https://www.google.com, https://one.one.one.one"))
        targets = [parse_target(s, defaults) for s in
                   ["1.1.1.1", "8.8.8.8", "https://www.google.com",
                    "https://one.one.one.one"]]

    alerts = AlertConfig(args.tg_token, args.tg_chat, args.webhook, args.alert_on)
    bus = EventBus(None if args.no_log else args.log, alerts)

    csv_fp = csv_writer = None
    csv_lock = threading.Lock()
    if args.csv:
        write_header = not args.csv.exists() or args.csv.stat().st_size == 0
        csv_fp = open(args.csv, "a", newline="", encoding="utf-8")
        csv_writer = csv.DictWriter(csv_fp, fieldnames=CSV_FIELDS)
        if write_header:
            csv_writer.writeheader()

    bus.emit("INFO", "netwatch", "start",
             f"Watching {len(targets)} target(s): " +
             ", ".join(t.name for t in targets) +
             f" | interval={args.interval}s timeout={args.timeout}s "
             f"warn={args.warn_ms}ms")

    stop = threading.Event()
    probers = [Prober(t, bus, csv_writer, csv_lock, diag_every=args.diag_every)
               for t in targets]
    routes = RouteMonitor(bus, deep=args.deep)
    for pr in probers:
        pr.start()
    routes.start()

    try:
        if args.dashboard:
            threading.Thread(target=dashboard_loop,
                             args=(probers, routes, stop, args.period),
                             daemon=True).start()
        end = time.monotonic() + args.duration if args.duration else None
        while not stop.wait(1.0):
            if end and time.monotonic() >= end:
                break
    except KeyboardInterrupt:
        print()
    finally:
        bus.emit("INFO", "netwatch", "stop", "Stopped")
        stop.set()
        routes.stop_evt.set()
        for pr in probers:
            pr.stop_evt.set()
        print("\n" + bold("Итоги:"))
        for pr in probers:
            print("  " + pr.line())
        if csv_fp:
            csv_fp.close()
        if bus.log_fp:
            bus.log_fp.close()
    down = any(p.state == "DOWN" for p in probers)
    return 1 if down else 0


if __name__ == "__main__":
    sys.exit(main())
