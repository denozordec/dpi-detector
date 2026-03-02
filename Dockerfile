FROM python:3.14-alpine

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cli/ ./cli/
COPY core/ ./core/
COPY utils/ ./utils/
COPY metrics/ ./metrics/
COPY dpi_detector.py .
COPY domains.txt .
COPY tcp16.json .
COPY config.py .
COPY whitelist_sni.txt .

# Prometheus metrics port
EXPOSE 9090

# ---------------------------------------------------------------------------
# RUN_MODE=once     — запустить тесты один раз и завершить контейнер
# RUN_MODE=schedule — запускать тесты по расписанию (daemon-режим)
# TESTS=123         — выбор тестов (1=DNS, 2=Домены, 3=TCP, 4=SNI), по умолчанию 123
# CHECK_INTERVAL=7200 — интервал между проверками в секундах (для schedule)
# ---------------------------------------------------------------------------
ENV RUN_MODE=schedule
ENV TESTS=123
ENV CHECK_INTERVAL=7200
ENV METRICS_PORT=9090
# ENV METRICS_USER=prometheus
# ENV METRICS_PASSWORD=secret

CMD ["python", "-u", "dpi_detector.py"]
