"""nw_export — форматтеры вывода netwatch: HTML-отчёт, Prometheus, InfluxDB line protocol.

Чистый stdlib. Данные берутся из CSV-лога проб (--csv) и JSONL-лога событий (--log),
то есть экспортёр работает оффлайном на уже накопленных файлах.
"""

from __future__ import annotations

import csv
import json
import time
from collections import defaultdict
from pathlib import Path
from typing import List, Optional


# ---------------------------------------------------------------------------
# Загрузка логов
# ---------------------------------------------------------------------------

def load_probes(csv_path: Path) -> List[dict]:
    rows = []
    if not csv_path or not csv_path.exists():
        return rows
    with open(csv_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            try:
                r["_rtt"] = float(r["rtt_ms"]) if r.get("rtt_ms") else None
            except ValueError:
                r["_rtt"] = None
            for k in ("avg_ms", "win_loss_pct", "jitter_ms", "p95_ms"):
                try:
                    r["_" + k] = float(r[k]) if r.get(k) else None
                except (ValueError, KeyError):
                    r["_" + k] = None
            rows.append(r)
    return rows


def load_events(jsonl_path: Path) -> List[dict]:
    evs = []
    if not jsonl_path or not jsonl_path.exists():
        return evs
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        try:
            evs.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return evs


def _fmt_ts(ts: str) -> str:
    """'2026-11-07T13:11:22+00:00' -> 'HH:MM:SS' (для подписей графика)."""
    try:
        return ts.split("T", 1)[1][:8]
    except IndexError:
        return ts


# ---------------------------------------------------------------------------
# HTML-отчёт (RTT-график SVG + таблица целей + лента инцидентов)
# ---------------------------------------------------------------------------

_STATE_COLORS = {"UP": "#2ecc71", "DEGRADED": "#f1c40f", "DOWN": "#e74c3c",
                 "UNKNOWN": "#7f8c8d"}


def _svg_chart(series: dict, w: int = 940, h: int = 220) -> str:
    """series: {target: [(idx, rtt_or_None)]} -> inline SVG multi-line chart."""
    pts_all = [v for s in series.values() for _, v in s if v is not None]
    if not pts_all:
        return "<p><i>нет данных RTT</i></p>"
    vmax = max(pts_all) * 1.15 or 1.0
    nmax = max(len(s) for s in series.values()) or 1
    pal = ["#3498db", "#e67e22", "#9b59b6", "#1abc9c", "#e74c3c", "#f1c40f",
           "#34495e", "#2ecc71"]
    parts = [f'<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" '
             f'style="background:#111;border-radius:8px">']
    # сетка + подписи оси Y
    for i in range(5):
        y = h - 24 - (h - 44) * i / 4
        val = vmax * i / 4
        parts.append(f'<line x1="46" y1="{y:.0f}" x2="{w-10}" y2="{y:.0f}" '
                     f'stroke="#333" stroke-width="1"/>')
        parts.append(f'<text x="6" y="{y+4:.0f}" fill="#888" font-size="11">'
                     f'{val:.0f}ms</text>')
    for j, (name, pts) in enumerate(sorted(series.items())):
        color = pal[j % len(pal)]
        d = []
        for idx, v in pts:
            if v is None:
                continue
            x = 46 + (w - 56) * idx / max(1, nmax - 1)
            y = h - 24 - (h - 44) * (v / vmax)
            d.append(f"{'M' if not d else 'L'}{x:.1f},{y:.1f}")
        if d:
            parts.append(f'<path d="{" ".join(d)}" fill="none" stroke="{color}" '
                         f'stroke-width="2"/>')
        # точки-провалы (потери) красным по нижней границе
        for idx, v in pts:
            if v is None:
                x = 46 + (w - 56) * idx / max(1, nmax - 1)
                parts.append(f'<circle cx="{x:.1f}" cy="{h-16}" r="3" fill="#e74c3c"/>')
        parts.append(f'<text x="{46 + j*130}" y="14" fill="{color}" font-size="12"'
                     f' font-family="monospace">&#9632; {name[:24]}</text>')
    parts.append("</svg>")
    return "".join(parts)


def render_html(csv_path: Path, events_path: Optional[Path], out: Path,
                title: str = "netwatch report") -> int:
    probes = load_probes(csv_path)
    events = load_events(events_path) if events_path else []
    by_tgt: dict = defaultdict(list)
    for r in probes:
        by_tgt[r["target"]].append(r)
    series = {t: [(i, r["_rtt"]) for i, r in enumerate(rows[-400:])]
              for t, rows in by_tgt.items()}

    inc = [e for e in events if e.get("level") in ("WARN", "CRIT")]
    rows_html = []
    for t in sorted(by_tgt):
        rows = by_tgt[t]
        last = rows[-1]
        n = len(rows)
        fails = sum(1 for r in rows if r["_rtt"] is None)
        states = {s: sum(1 for r in rows if r["state"] == s)
                  for s in ("UP", "DEGRADED", "DOWN")}
        rtts = [r["_rtt"] for r in rows if r["_rtt"] is not None]
        avg = sum(rtts) / len(rtts) if rtts else 0
        p95 = sorted(rtts)[int(0.95 * (len(rtts) - 1))] if rtts else 0
        st_color = _STATE_COLORS.get(last["state"], "#7f8c8d")
        rows_html.append(
            f"<tr><td><b>{t}</b></td>"
            f"<td style='color:{st_color}'>{last['state']}</td>"
            f"<td>{n}</td><td>{fails} ({100*fails/max(1,n):.1f}%)</td>"
            f"<td>{avg:.1f} ms</td><td>{p95:.1f} ms</td>"
            f"<td>{states['UP']} / {states['DEGRADED']} / {states['DOWN']}</td></tr>")

    ev_html = []
    for e in inc[-200:][::-1]:
        lvl = e.get("level", "?")
        col = "#e74c3c" if lvl == "CRIT" else "#f1c40f"
        ev_html.append(f"<div class='ev'><span style='color:{col}'>[{lvl}]</span> "
                       f"<span class='ts'>{_fmt_ts(e.get('ts',''))}</span> "
                       f"<b>{e.get('target','?')}</b> <code>{e.get('kind','?')}</code> "
                       f"&mdash; {str(e.get('msg',''))[:160]}</div>")

    doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>{title}</title>
<style>
body{{background:#0d1117;color:#c9d1d9;font:14px/1.5 system-ui,sans-serif;margin:24px}}
h1{{font-size:20px}} h2{{font-size:16px;margin-top:28px;color:#8b949e}}
table{{border-collapse:collapse;width:100%}} td,th{{padding:6px 10px;border-bottom:1px solid #21262d;text-align:left;font-family:ui-monospace,monospace}}
th{{color:#8b949e}} .ev{{padding:3px 0;border-bottom:1px dashed #21262d}} .ts{{color:#8b949e}} code{{background:#161b22;padding:1px 5px;border-radius:4px}}
.muted{{color:#8b949e}}
</style></head><body>
<h1>&#128225; {title}</h1>
<p class="muted">проб: {len(probes)} | целей: {len(by_tgt)} | инцидентов (WARN/CRIT): {len(inc)} |
сгенерировано: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<h2>RTT по целям (красные точки снизу &mdash; потеря пробы)</h2>
{_svg_chart(series)}
<h2>Сводка по целям</h2>
<table><tr><th>цель</th><th>сейчас</th><th>проб</th><th>потерь</th><th>avg RTT</th>
<th>p95 RTT</th><th>UP/DEG/DOWN</th></tr>{''.join(rows_html)}</table>
<h2>Инциденты</h2>
{''.join(ev_html) or '<p class="muted">инцидентов нет &#127881;</p>'}
</body></html>"""
    out.write_text(doc, encoding="utf-8")
    print(f"HTML-отчёт записан: {out} ({len(doc)} байт)")
    return 0


# ---------------------------------------------------------------------------
# Prometheus text exposition format
# ---------------------------------------------------------------------------

def _label_escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_prometheus(csv_path: Path, events_path: Optional[Path],
                      prefix: str = "netwatch") -> int:
    probes = load_probes(csv_path)
    events = load_events(events_path) if events_path else []
    latest: dict = {}
    for r in probes:
        latest[r["target"]] = r          # последняя проба на цель
    state_num = {"UP": 2, "DEGRADED": 1, "DOWN": 0, "UNKNOWN": 0}
    lines = []

    def metric(name, labels, value, mtype="gauge", help_=None):
        lbl = ",".join(f'{k}="{_label_escape(str(v))}"' for k, v in labels.items())
        head = f"# TYPE {prefix}_{name} {mtype}"
        if help_ and head not in seen:
            lines.append(f"# HELP {prefix}_{name} {help_}")
        if head not in seen:
            lines.append(head)
            seen.add(head)
        lines.append(f"{prefix}_{name}{{{lbl}}} {value}")

    seen = set()
    for t, r in sorted(latest.items()):
        base = {"target": t}
        metric("up", base, state_num.get(r["state"], 0),
               help_="2=UP, 1=DEGRADED, 0=DOWN/UNKNOWN")
        if r["_rtt"] is not None:
            metric("rtt_ms", base, round(r["_rtt"], 2), help_="последний RTT, мс")
        if r.get("_avg_ms") is not None:
            metric("rtt_avg_ms", base, round(r["_avg_ms"], 2))
        if r.get("_p95_ms") is not None:
            metric("rtt_p95_ms", base, round(r["_p95_ms"], 2))
        if r.get("_jitter_ms") is not None:
            metric("jitter_ms", base, round(r["_jitter_ms"], 2))
        metric("loss_pct", base, r.get("_win_loss_pct") or 0.0)
        metric("consec_fails", base, int(r.get("consec_fails") or 0))

    kind_counts: dict = defaultdict(int)
    tgt_kind: dict = defaultdict(int)
    for e in events:
        kind_counts[e.get("kind", "?")] += 1
        tgt_kind[(e.get("target", "?"), e.get("kind", "?"))] += 1
    for k, n in sorted(kind_counts.items()):
        metric("events_total", {"kind": k}, n, mtype="counter")
    for (t, k), n in sorted(tgt_kind.items()):
        metric("events_by_target_total", {"target": t, "kind": k}, n, mtype="counter")
    print("\n".join(lines))
    return 0


# ---------------------------------------------------------------------------
# InfluxDB line protocol
# ---------------------------------------------------------------------------

def render_influx(csv_path: Path, measurement: str = "probe") -> int:
    probes = load_probes(csv_path)
    out_lines = []
    for r in probes:
        tags = f"target={_lp(r['target'])},state={_lp(r['state'])}"
        fields = [f"total={int(float(r.get('total') or 0))}i",
                  f"failures={int(float(r.get('failures') or 0))}i",
                  f"loss_pct={float(r.get('_win_loss_pct') or 0):g}"]
        if r["_rtt"] is not None:
            fields.append(f"rtt_ms={r['_rtt']:g}")
        if r.get("_avg_ms") is not None:
            fields.append(f"avg_ms={r['_avg_ms']:g}")
        if r.get("_jitter_ms") is not None:
            fields.append(f"jitter_ms={r['_jitter_ms']:g}")
        ts_ns = _iso_to_ns(r.get("ts", ""))
        out_lines.append(f"{measurement},{tags} {','.join(fields)} {ts_ns}")
    print("\n".join(out_lines))
    return 0


def _lp(v: str) -> str:
    return str(v).replace(",", "\\,").replace("=", "\\=").replace(" ", "\\ ")


def _iso_to_ns(ts: str) -> int:
    try:
        struct = time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
        return int(time.mktime(struct) * 1e9)
    except Exception:
        return int(time.time() * 1e9)
