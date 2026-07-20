FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install -r /tmp/requirements.txt

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS runtime

ARG VERSION=1.1.0
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="Auth Service" \
      org.opencontainers.image.description="可自托管的多应用统一认证服务" \
      org.opencontainers.image.source="https://github.com/HyxiaoGe/auth-service" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}"

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 auth && \
    useradd --uid 10001 --gid auth --create-home --shell /usr/sbin/nologin auth

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=auth:auth app ./app
COPY --chown=auth:auth alembic ./alembic
COPY --chown=auth:auth scripts ./scripts
COPY --chown=auth:auth alembic.ini ./alembic.ini
COPY --chown=auth:auth LICENSE /licenses/LICENSE

RUN mkdir -p /app/keys && \
    touch /app/keys/.volume-owner && \
    chown -R auth:auth /app/keys

USER auth

EXPOSE 8100

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8100"]
