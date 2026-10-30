# netwatch 🔍

Лёгкий инструмент для **отслеживания сетевых ошибок и проблем подключения**.
Один файл, чистый Python stdlib (3.8+), ноль зависимостей, работает на Linux/macOS/Windows.

## Что детектит

| Проблема | Как ловится | Уровень |
|---|---|---|
| Хост недоступен / нет связи | ICMP-пинг → TCP-фолбэк, `fails_to_down` фейлов подряд | `CRIT` (down) |
| Обрыв default route, смена шлюза/интерфейса | парсинг `ip route show default` (Linux) | `CRIT`/`WARN` |
| DNS не резолвится | `getaddrinfo` / `URLError` | `CRIT` (dns_failure) |
| Порт закрыт | TCP connect → `connection_refused` | `WARN` (degraded) |
| Медленные ответы | RTT/TTFB > `--warn-ms` | `WARN` (degraded) |
| Таймауты соединения/HTTP | socket timeout | как failure |
| TLS-ошибки сертификата | `SSLCertVerificationError` | failure + tls_error |
| Сервер падает (5xx) | HTTP status ≥ 500 | failure |
| Потеря пакетов / дребезг | % потерь в окне + jitter по последним 10 RTT | метрики |
| ICMP блокируется, но сеть есть | автопереключение на TCP-пинг | `WARN` (icmp_blocked) |

Каждый переход `UP ↔ DEGRADED ↔ DOWN` — одно событие (без спама), все пробы — в CSV.

## Быстрый старт

```bash
# просто запусти — возьмёт стандартный набор целей
python3 netwatch.py

# свои цели: IP / домен / host:port / URL / alias:spec
python3 netwatch.py --targets 8.8.8.8 gateway:192.168.1.1 db:localhost:5432 https://example.com

# live-дашборд + CSV исторических проб
python3 netwatch.py --config netwatch.toml --dashboard --csv probes.csv

# часовой прогон с алертами во webhook
python3 netwatch.py -t 1.1.1.1 https://mysite.ru --duration 3600 \
    --webhook https://hooks.example.com/netwatch --alert-on WARN

# разбор накопленного журнала
python3 netwatch.py --report netwatch-events.jsonl
```

Exit code: `0` — всё живо, `1` — хоть одна цель DOWN (удобно в cron/CI).

## Пороги чувствительности

```
-i/--interval 5     период проб          --warn-ms 250      порог «медленно»
--timeout 2         таймаут пробы        --fails-to-down 2  фейлов подряд до DOWN
```

## Алерты

* терминал (цветные CRIT!/WARN события);
* **Telegram**: `--tg-token <bot_token> --tg-chat <chat_id>`;
* **generic webhook**: `--webhook <url>` — POST JSON события (подойдёт для Slack-compatible, n8n, своей ручки).

## Логи

* `netwatch-events.jsonl` — структурированные события (`ts, level, target, kind, msg + метрики`);
* `--csv probes.csv` — каждая проба: state, rtt_ms, error, loss%, avg/max/jitter, consec_fails.

## systemd (демон на сервере)

```ini
# /etc/systemd/system/netwatch.service
[Unit]
Description=netwatch connectivity monitor
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/netwatch/netwatch.py --config /opt/netwatch/netwatch.toml --csv /var/log/netwatch-probes.csv
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
```

## Как это работает (кратко)

Каждая цель — отдельный поток-пробник (`Prober`). Проба возвращает `(rtt_ms, error)`;
скользящее окно считает потери/jitter; машина состояний UP/DEGRADED/DOWN генерирует
события только на переходах. Отдельный `RouteMonitor` следит за таблицей маршрутизации —
это позволяет различить «лёг хост» от «лег весь канал/провайдер».
