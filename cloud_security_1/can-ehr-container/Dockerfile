# Hardened multi-stage build for the CAN EHR simulator.
# Stage 1 installs dependencies; stage 2 is a minimal Chainguard (Wolfi) image:
# no shell, no package manager, no pip, and 0 known CVEs at build time.

# ---- Build stage ----
FROM cgr.dev/chainguard/python:latest-dev@sha256:8c06d75b497c156bb7a42fedb6480fe2c1865e93538215e4a0f7bf99a03f1f99 AS build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Root is only used in this throwaway build stage; the runtime stage runs as non-root
USER root
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-compile --target /deps -r requirements.txt

# ---- Runtime stage ----
FROM cgr.dev/chainguard/python:latest@sha256:b7af1ae90e2fcfb5c32be03908e74d32fdfd64156c2b7c535bd3e497e7846d84

LABEL org.opencontainers.image.title="can-ehr-simulator" \
      org.opencontainers.image.description="Care Access Navigator EHR simulator (hardened)" \
      org.opencontainers.image.version="2.0"

ENV PYTHONPATH=/deps \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY --from=build --chown=root:root --chmod=0555 /deps /deps
COPY --chown=root:root --chmod=0444 app.py .

# UID 65532 = Chainguard "nonroot"; files above are root-owned and read-only to it
USER 65532:65532

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"]

# Production WSGI server instead of the Flask development server
ENTRYPOINT ["python3", "-m", "gunicorn"]
CMD ["--bind", "0.0.0.0:8080", "--workers", "2", "--worker-tmp-dir", "/tmp", "--access-logfile", "-", "app:app"]
