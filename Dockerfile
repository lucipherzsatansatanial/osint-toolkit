FROM python:3.13-slim
WORKDIR /app
RUN useradd -r -u 10001 -d /app osint
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY static ./static
COPY detections ./detections
COPY docs ./docs
COPY docker/entrypoint.py ./docker/entrypoint.py
RUN mkdir -p /app/data && chown osint /app/data
ENV OSINT_DB_PATH=/app/data/osint.db
VOLUME ["/app/data"]
EXPOSE 8000
# Starts as root only to give the (possibly root-owned) data disk to the app user, then drops to uid 10001.
CMD ["python", "/app/docker/entrypoint.py"]
