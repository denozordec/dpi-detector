<p align="center">
  <img src="https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/images/logo.jpg" width="100%">
  <br>
  <i>«Маяк у гаснущего горизонта свободного интернета»</i><br>
  Сквозь цифровые сумерки. Смотритель маяка, <a href="https://github.com/Runnin4ik"><b>Runni</b></a>
</p>

# 🔍 DPI Detector
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://github.com/denozordec/dpi-detector)

Инструмент для анализа цензуры трафика в России: обнаруживает и классифицирует блокировки сайтов, хостингов и CDN (TCP16-20 блокировки), а также подмену DNS-запросов провайдером.

> **Fork** от [Runnin4ik/dpi-detector](https://github.com/Runnin4ik/dpi-detector) с расширенными возможностями запуска через Docker.

![Пример результатов](https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/images/screenshot.png)

## 🎯 Возможности

- **TCP 16-20KB блокировка** — обнаруживает обрыв соединения к CDN и хостингам после передачи 14-34KB
- **Подбор белых SNI для AS хостингов/CDN**
- **Проверка доступности заблокированных сайтов** — тестирует TLS 1.2, TLS 1.3 и HTTP
- **Проверка DNS** — выявляет перехват UDP/53, подмену IP-адресов заглушками и блокировку DoH
- **Классификация ошибок** — различает TCP RST, Connection Abort, Handshake/Read Timeout, TLS MITM, SNI-блокировку и другие
- **Гибкая настройка** — таймауты, потоки, свои списки доменов, DNS-серверы и IPv4-only режим
- **Два режима запуска** — одиночная проверка (`once`) или фоновый демон по расписанию (`schedule`)

### ⚙️ Кастомизация
Следующие файлы могут быть переопределены:

1. `domains.txt` — список доменов для проверки
2. `tcp16.json` — цели для теста TCP 16-20KB
3. `config.py` — конфигурация
4. `whitelist_sni.txt` — список белых SNI для подбора рабочих

> [!WARNING]  
> Если у вас запущены средства обхода блокировок (например, zapret или GoodbyeDPI), результаты тестов будут искажены. Чтобы узнать реальное состояние фильтров вашего провайдера, выключите их перед началом проверки или убедитесь, что они работают в режиме обработки всех пакетов (режим ALL), а не только по списку.

---

## 🐋 Docker

### Переменные окружения

| Переменная | Значения | По умолчанию | Описание |
|---|---|---|---|
| `RUN_MODE` | `once` / `schedule` | `schedule` | Режим запуска |
| `TESTS` | комбинация `1234` | `123` | Набор тестов (1=DNS, 2=Домены, 3=TCP, 4=SNI) |
| `CHECK_INTERVAL` | секунды | `7200` | Интервал между проверками (только `schedule`) |
| `METRICS_PORT` | порт | `9090` | Порт Prometheus-метрик |
| `METRICS_USER` | строка | — | Basic Auth логин для метрик |
| `METRICS_PASSWORD` | строка | — | Basic Auth пароль для метрик |

---

### 🔂 Режим `once` — одиночная проверка

Запустить тесты один раз и завершить контейнер. Удобно для cron, CI или ручного запуска.

```bash
# Сборка и запуск
git clone https://github.com/denozordec/dpi-detector.git
cd dpi-detector
docker compose run --rm dpi-once
```

Или напрямую через `docker run`:
```bash
docker run --rm \
  -e RUN_MODE=once \
  -e TESTS=123 \
  $(docker build -q .)
```

С монтированием своих файлов:
```bash
docker compose run --rm \
  -v $(pwd)/domains.txt:/app/domains.txt \
  -v $(pwd)/config.py:/app/config.py \
  dpi-once
```

---

### 🔁 Режим `schedule` — фоновый демон

Запустить как сервис: тесты повторяются каждые `CHECK_INTERVAL` секунд, метрики доступны на порту 9090 для Prometheus/Grafana.

```bash
git clone https://github.com/denozordec/dpi-detector.git
cd dpi-detector
docker compose up -d dpi-schedule
```

Посмотреть логи:
```bash
docker compose logs -f dpi-schedule
```

Остановить:
```bash
docker compose down
```

С кастомными файлами (`docker-compose.override.yml`):
```yaml
services:
  dpi-schedule:
    volumes:
      - ./domains.txt:/app/domains.txt
      - ./config.py:/app/config.py
```

---

### 📊 Prometheus-метрики (только `schedule`)

Метрики доступны по адресу `http://<host>:9090/metrics`.

Пример конфига для `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: dpi-detector
    static_configs:
      - targets: ['localhost:9090']
    basic_auth:
      username: prometheus
      password: secret  # укажите свой пароль из METRICS_PASSWORD
```

> [!WARNING]
> Обязательно смените `METRICS_PASSWORD` в `docker-compose.yml` перед публичным деплоем!

---

### ⚡ Быстрые примеры

```bash
# Одиночная проверка, тесты 1+2+3
docker compose run --rm dpi-once

# Одиночная проверка, только DNS + Домены
docker run --rm -e RUN_MODE=once -e TESTS=12 $(docker build -q .)

# Фоновый демон, проверка каждый час
docker run -d \
  -e RUN_MODE=schedule \
  -e TESTS=123 \
  -e CHECK_INTERVAL=3600 \
  -p 9090:9090 \
  $(docker build -q .)

# Фоновый демон через compose (по умолчанию каждые 2 часа)
docker compose up -d dpi-schedule
```

---

## 🖥️ Интерактивный запуск (без Docker)

При запуске без переменной `RUN_MODE` скрипт задаёт вопросы в интерактивном режиме.

### Python 3.8+

**Требования:** httpx>=0.28, rich>=14.3

```bash
git clone https://github.com/denozordec/dpi-detector.git
cd dpi-detector
python -m pip install -r requirements.txt
python dpi_detector.py
```

После выбора тестов появится вопрос о режиме запуска:
```
Режим запуска:
  1 — Одиночная проверка (запустить и выйти)
  2 — Фоновый режим (повторять по расписанию)
```

### 🪟 Windows (Готовые сборки)

Скачайте `.exe` в разделе [Releases](https://github.com/Runnin4ik/dpi-detector/releases) оригинального репозитория:

- **[Windows 10 / 11](https://github.com/Runnin4ik/dpi-detector/releases/download/v2.0.1/dpi_detector_v2.0.1_win10.exe)**
- **[Windows 7 / 8](https://github.com/Runnin4ik/dpi-detector/releases/download/v2.0.1/dpi_detector_v2.0.1_win7.exe)**

Для кастомизации положите `domains.txt`, `tcp16.json`, `config.py`, `whitelist_sni.txt` рядом с `.exe`.

---

## 🤝 Вклад в проект

Приветствуются Issue и Pull Request'ы!

## 📜 Лицензия

[MIT License](LICENSE) — свободное использование, модификация и распространение.

## ⚠️ Дисклеймер

Этот инструмент предназначен исключительно для образовательных и диагностических целей. Автор не несет ответственности за использование данного ПО.

## 🙏 Благодарности

- Проекту [hyperion-cs/dpi-checkers](https://github.com/hyperion-cs/dpi-checkers) за вдохновение
- **0ka** за помощь и консультации
- [Runnin4ik](https://github.com/Runnin4ik) за оригинальный инструмент
