FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

COPY app ./app
COPY tests ./tests
COPY verify ./verify

EXPOSE 8000

# 默认启动 web 服务；verify 服务以 command 覆盖为一次性验收。
CMD ["python", "-m", "app.server"]
