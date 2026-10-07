# 自包含镜像：代码在镜像内、数据持久化到 /data。
# Self-contained image: code baked in; data persists under /data.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# tzdata 供 TZ 生效；gosu 用于 PUID/PGID 降权；bash 供 Shell 脚本与入口。
# tzdata for TZ; gosu to drop privileges to PUID/PGID; bash for scripts/entrypoint.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata gosu bash ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . .

RUN chmod +x deploy/docker-entrypoint.sh deploy/docker-healthcheck.py

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python /app/deploy/docker-healthcheck.py

ENTRYPOINT ["/app/deploy/docker-entrypoint.sh"]
