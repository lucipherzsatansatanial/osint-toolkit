FROM python:3.13-slim
WORKDIR /app
RUN useradd -r -u 10001 osint
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY static ./static
COPY detections ./detections
RUN mkdir -p /app/data && chown osint /app/data
USER osint
ENV OSINT_DB_PATH=/app/data/osint.db
VOLUME ["/app/data"]
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips=*"]
