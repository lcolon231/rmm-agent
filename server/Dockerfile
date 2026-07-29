# syntax=docker/dockerfile:1
# NodeLink RMM backend (FastAPI) — production container image.
# Pinned to CPython 3.12: requirements.txt native deps do not publish 3.14 wheels.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=10000

WORKDIR /app

# Install dependencies first so this layer caches across code changes.
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Application code (Docker build context is the server/ directory).
COPY . ./

# Normalize entrypoint line endings (repo may be edited on Windows) and mark it
# executable so the shebang works regardless of the checkout's file mode.
RUN sed -i 's/\r$//' docker-entrypoint.sh && chmod +x docker-entrypoint.sh

EXPOSE 10000

ENTRYPOINT ["./docker-entrypoint.sh"]
