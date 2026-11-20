FROM mongo:7.0 AS mongo-tools

FROM python:3.12-slim
WORKDIR /work
# mongodump/mongorestore for Chapter 14 "Back up now" and "Verify restore" (copied from the official image).
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libgssapi-krb5-2 && rm -rf /var/lib/apt/lists/*
COPY --from=mongo-tools /usr/bin/mongodump /usr/local/bin/mongodump
COPY --from=mongo-tools /usr/bin/mongorestore /usr/local/bin/mongorestore
RUN mongodump --version && mongorestore --version
COPY requirements.txt requirements-app.txt ./
RUN pip install --no-cache-dir --default-timeout=120 --retries 8 -r requirements.txt -r requirements-app.txt
COPY app app
COPY data data
# Lab source: the Experiments pages show it, and the Chapter 16 fraud service is imported from it.
# (compose.yaml also mounts ./labs read-only, so local edits appear without a rebuild.)
COPY labs labs
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
