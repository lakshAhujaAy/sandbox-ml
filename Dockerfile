# One image, one port: dashboard + API + Redis + ML worker + headless Chromium.
#   docker build -t malsandbox .
#   docker run -p 7860:7860 -e BASIC_AUTH_PASSWORD=choose-one malsandbox
FROM node:20-slim AS web
WORKDIR /web
COPY frontend/package.json ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PORT=7860 \
    SANDBOX_MODE=subprocess MAX_WORKERS=2 ML_TIMEOUT=60 SANDBOX_TIMEOUT=45 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    MLFLOW_TRACKING_URI=sqlite:////tmp/mlflow.db
RUN apt-get update && apt-get install -y --no-install-recommends redis-server libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 app && mkdir /app && chown app /app
WORKDIR /app
COPY backend/requirements-deploy.txt .
RUN pip install -r requirements-deploy.txt \
    && pip install torch==2.3.0 torchvision==0.18.0 --index-url https://download.pytorch.org/whl/cpu \
    && playwright install --with-deps chromium \
    && chmod -R a+rX /ms-playwright
COPY --chown=app backend/ /app/
COPY --from=web --chown=app /web/build /app/frontend_build
COPY --chown=app deploy/start.sh /app/start.sh
USER app
EXPOSE 7860
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:%s/health'%os.environ.get('PORT','7860'))"
CMD ["bash", "/app/start.sh"]
