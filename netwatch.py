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
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple, List

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

    def describe(self) -> str:
        if self.url:
            return self.url
        if self.port:
            return f"{self.host}:{self.port}"
        return self.host or self.name


def parse_target(spec: str, defaults: TargetConfig) -> TargetConfig:
    """'alias:host:443' | 'https://site/path' | 'host:443' | 'host' | '1.1.1.1'."""
    name, rest = None, spec
    # alias:остальное — alias не должен быть схемой и не должен быть числом
    m = re.match(r"^([A-Za-z][A-Za-z0-9_-]*):(.+)$", spec)
    if m and not spec.startswith(("http://", "https://")):
        cand_alias, cand_rest = m.group(1), m.group(2)
        if ":" in cand_rest or "/" in cand_rest or cand_rest[0].isdigit():
            name, rest = cand_alias, cand_rest
        elif not re.match(r"^\d+$", cand_rest):
            # 'alias:somehost' — тоже валидный префикс имени
            name, rest = cand_alias, cand_rest

    t = TargetConfig(name=name or rest)
    t.interval = defaults.interval
    t.timeout = defaults.timeout
    t.latency_warn_ms = defaults.latency_warn_ms
    t.fails_to_down = defaults.fails_to_down

    if rest.startswith(("http://", "https://")):
        pr = urllib.parse.urlparse(rest)
        t.url = rest
        t.host = pr.hostname
        t.port = pr.port or (443 if pr.scheme == "https" else 80)
    elif ":" in rest and rest.rsplit(":", 1)[-1].isdigit():
        t.host, p = rest.rsplit(":", 1)
        t.port = int(p)
    else:
        t.host = rest
    if not name:
        t.name = t.describe()
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
            "jitter_ms": round(self.jitter, 1) if self.jitter is not None else None,
            "consec_fails": self.consec_fails,
        }


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

    def emit(self, level: str, target: str, kind: str, msg: str, extra: dict = None):
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
# Монитор default route (Linux)
# -----------------------------------------------------------------------------

class RouteMonitor(threading.Thread):
    def __init__(self, bus: EventBus, every: float = 10.0):
        super().__init__(daemon=True)
        self.bus = bus
        self.every = every
        self.last_state: Optional[dict] = None
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

    def run(self):
        while not self.stop_evt.wait(self.every):
            st = self.current_state()
            if st is None:
                continue
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


# -----------------------------------------------------------------------------
# Пробник одной цели
# -----------------------------------------------------------------------------

class Prober(threading.Thread):
    def __init__(self, cfg: TargetConfig, bus: EventBus,
                 csv_writer=None, csv_lock=None):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.bus = bus
        self.stats = Stats()
        self.csv_writer = csv_writer
        self.csv_lock = csv_lock
        self.stop_evt = threading.Event()
        self.state = "UNKNOWN"
        self._reported_state = None
        self._icmp_blocked = False

    # --- одна проба -----------------------------------------------------------
    def probe_once(self) -> Tuple[Optional[float], Optional[str]]:
        cfg = self.cfg
        if cfg.url:
            rtt, status, err = http_probe(cfg.url, cfg.timeout)
            if err is None and status is not None and status >= 500:
                err = f"http_5xx_{status}"
            elif err is None and status is not None and 400 <= status < 500:
                # сервер отвечает => сеть работает; 4xx это не сетевая проблема
                pass
            return rtt, err
        if cfg.port:
            return tcp_connect(cfg.host, cfg.port, cfg.timeout)
        # ICMP-цель
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

    # --- оценка результата -----------------------------------------------------
    def evaluate(self, rtt: Optional[float], err: Optional[str]):
        cfg, st = self.cfg, self.stats
        hard_fail = rtt is None
        st.add(rtt if not hard_fail else None)

        # connection_refused: ртт измерена, хост жив — это DEGRADED, не DOWN
        if err == "connection_refused":
            new = "DEGRADED"
        elif hard_fail and st.consec_fails < cfg.fails_to_down:
            new = self.state if self.state in ("UP", "DEGRADED") else "UNKNOWN"
        elif hard_fail:
            new = "DOWN"
        elif rtt is not None and rtt > cfg.latency_warn_ms:
            new = "DEGRADED"
        else:
            new = "UP"

        if err and err.startswith("dns_error"):
            self.bus.emit("CRIT", cfg.name, "dns_failure",
                          f"DNS resolution FAILED: {err}")

        if new != self._reported_state:
            snap = st.snapshot()
            if new == "DOWN":
                self.bus.emit("CRIT", cfg.name, "down",
                              f"UNREACHABLE ({err or 'no reply'}) | "
                              f"consec_fails={snap['consec_fails']} loss={snap['win_loss_pct']}%",
                              {"error": err, **snap})
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
        icon = {"UP": " ● ", "DOWN": " ● ", "DEGRADED": " ● "}.get(self.state, " ○ ")
        rtt = f"{st.last_ok:.0f}ms" if st.last_ok is not None else "-"
        jit = f"{st.jitter:.0f}ms" if st.jitter is not None else "-"
        probe_kind = "http" if st and self.cfg.url else ("tcp" if self.cfg.port else "icmp")
        return (f"{col(icon)}{bold(self.cfg.name.ljust(30))} {col(self.state.ljust(9))} "
                f"[{probe_kind:>4}] rtt={rtt:>7} avg={st.avg_rtt:>6.0f}ms "
                f"jit={jit:>6} loss={st.win_loss_pct:>5.1f}% "
                f"({st.failures}/{st.total})")


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
    kv: dict = {}

    def flush():
        nonlocal kv
        if section == "target" and (kv.get("host") or kv.get("url")):
            t = TargetConfig(name=kv.get("name") or kv.get("host") or kv.get("url"))
            t.host = kv.get("host")
            t.url = kv.get("url")
            t.port = int(kv["port"]) if kv.get("port") else None
            for fnum in ("interval", "timeout", "latency_warn_ms"):
                if kv.get(fnum):
                    setattr(t, fnum, float(kv[fnum]))
            if kv.get("fails_to_down"):
                t.fails_to_down = int(kv["fails_to_down"])
            targets.append(t)
        kv = {}

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"\[+\s*(\w+)\s*\]+\s*$", line)   # принимает [target] и [[target]]
        if m:
            flush()
            section = m.group(1)
            continue
        m = re.match(r'^(\w+)\s*=\s*"?([^"]*)"?\s*$', line)
        if m and section == "target":
            kv[m.group(1)] = m.group(2)
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
    crit_kinds = {"down", "dns_failure", "route_lost"}
    warn_kinds = {"degraded", "route_switch", "icmp_blocked"}
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
# CLI
# -----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netwatch", formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Монитор сетевых ошибок и проблем подключения.")
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
    p.add_argument("--report", type=Path, metavar="JSONL",
                   help="показать отчёт по логу и выйти")
    p.add_argument("--duration", type=float, help="автоостановка через N секунд")
    return p


CSV_FIELDS = ["ts", "target", "state", "rtt_ms", "error", "total", "failures",
              "loss_pct", "win_loss_pct", "avg_ms", "last_ms", "max_ms",
              "jitter_ms", "consec_fails"]


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.report:
        if not args.report.exists():
            print(bad(f"лог не найден: {args.report}"), file=sys.stderr)
            return 2
        report(args.report)
        return 0

    defaults = TargetConfig(name="_", interval=args.interval, timeout=args.timeout,
                            latency_warn_ms=args.warn_ms,
                            fails_to_down=args.fails_to_down)
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
    probers = [Prober(t, bus, csv_writer, csv_lock) for t in targets]
    routes = RouteMonitor(bus)
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
