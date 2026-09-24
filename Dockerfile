FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install -U pip && pip install -r /app/requirements.txt

COPY . /app

# 单进程运行（内置调度器 + 进程内线程池，禁止多 worker）
CMD ["python", "app.py"]
