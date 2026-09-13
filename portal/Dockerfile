FROM python:3.12-slim
ARG COSIGN_VERSION=2.6.1
ARG COSIGN_SHA256=064954c5d8c7e3b28188eee5b1727b31c411550bc5fefd41aa672d3c761d103a
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl --fail --location --retry 3 "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" -o /tmp/cosign \
    && echo "${COSIGN_SHA256}  /tmp/cosign" | sha256sum -c - \
    && install -m 0755 /tmp/cosign /usr/local/bin/cosign \
    && rm /tmp/cosign && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
