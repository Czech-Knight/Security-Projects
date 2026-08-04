FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    YASHSEC_CONTAINER_MODE=true \
    YASHSEC_HOST=0.0.0.0 \
    YASHSEC_PORT=8787 \
    YASHSEC_DATA_DIR=/app/data

WORKDIR /app

RUN groupadd --system yashsec && useradd --system --gid yashsec --home-dir /app yashsec

COPY requirements.txt ./
RUN python -m pip install --upgrade pip && python -m pip install -r requirements.txt

COPY --chown=yashsec:yashsec app ./app
COPY --chown=yashsec:yashsec sample_targets ./sample_targets
RUN mkdir -p /app/data/repositories /app/data/reports /app/data/runtime /app/data/backups /app/data/secrets /app/data/logs \
    && chown -R yashsec:yashsec /app/data

USER yashsec
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.getenv('PORT','8787'), timeout=3)"

CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8787}"]
