# Version de Trivy (scanner de CVE). Gardez-la à jour : les OS récents
# (ex. Debian 13, Ubuntu 26.04) ne sont reconnus que par les versions récentes.
ARG TRIVY_VERSION=0.75.0
FROM aquasec/trivy:${TRIVY_VERSION} AS trivy

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST_ROOT=/host \
    STATE_FILE=/data/state.json \
    TRIVY_CACHE_DIR=/data/trivy-cache

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vanguarea_bot ./vanguarea_bot

VOLUME ["/data"]
CMD ["python", "-m", "vanguarea_bot"]
