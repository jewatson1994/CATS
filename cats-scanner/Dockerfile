ARG BASE_IMAGE=alpine:3.22
FROM ${BASE_IMAGE}

ARG CATS_SCANNER_VERSION=0.1.0
ARG GRYPE_VERSION=packaged
ARG SYFT_VERSION=packaged
ARG TRIVY_VERSION=0.69.3
ARG TRIVY_SHA256=1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75
ARG DOCKLE_VERSION=0.4.15
ARG DOCKLE_SHA256=8bfc9183d1d3d67800edb45bea4bb63ddf1d28bec5f89944075a07007d79caad
ARG HELM_VERSION=4.2.3
ARG HELM_SHA256=e9b88b4ee95b18c706839c28d3a0220e5bc470e9cd9262410c90793c45ff8b7c
ARG COPA_VERSION=0.14.1
ARG COPA_SHA256=a780f62c054f60cd1aecbbf4a4b2665a816aa852534e6b0b9592cf96a327fdc9
ARG GRYPE_DB_UPDATE_URL=https://grype.anchore.io/databases/v6/latest.json
ARG GRYPE_DB_REFRESH=unset
ARG TARGETARCH=amd64

LABEL org.opencontainers.image.title="CatScan" \
      org.opencontainers.image.description="CATS offline container scanning runner image" \
      org.opencontainers.image.version="${CATS_SCANNER_VERSION}" \
      cats.grype.version="${GRYPE_VERSION}" \
      cats.syft.version="${SYFT_VERSION}" \
      cats.trivy.version="${TRIVY_VERSION}" \
      cats.dockle.version="${DOCKLE_VERSION}" \
      cats.helm.version="${HELM_VERSION}" \
      cats.copa.version="${COPA_VERSION}"

RUN apk add --no-cache \
      bash \
      ca-certificates \
      coreutils \
      curl \
      docker \
      docker-cli-buildx \
      buildkit \
      git \
      grep \
      gzip \
      jq \
      miller \
      python3 \
      py3-yaml \
      sed \
      tar \
      unzip \
      util-linux \
      wget \
      yq \
      zstd \
      syft \
      grype

# Place one PEM-encoded enterprise CA bundle (or individual public *.crt
# files) in certs/. A bundle may contain both roots and the intermediate.
# Trust is installed before pinned tools are downloaded.
COPY certs /usr/local/share/ca-certificates
RUN find /usr/local/share/ca-certificates -type f -name '*.crt' -exec chmod 0644 {} \; \
    && update-ca-certificates \
    && if [ -f /usr/local/share/ca-certificates/host-ca-bundle.crt ]; then \
         cat /usr/local/share/ca-certificates/host-ca-bundle.crt >> /etc/ssl/certs/ca-certificates.crt; \
       fi

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# A disconnected build can supply these exact archives in tool-archives/. If
# they are absent, the immutable version URLs are downloaded and then checked
# against the pinned SHA-256 values above. CATScan currently targets amd64,
# matching the GitLab runner and production VM architecture.
COPY tool-archives /opt/catscan/tool-archives
RUN set -eux; \
    test "$TARGETARCH" = "amd64"; \
    trivy_archive="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    if [ -f "/opt/catscan/tool-archives/${trivy_archive}" ]; then \
      cp "/opt/catscan/tool-archives/${trivy_archive}" "/tmp/${trivy_archive}"; \
    else \
      curl --fail --location --silent --show-error \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${trivy_archive}" \
        --output "/tmp/${trivy_archive}"; \
    fi; \
    echo "${TRIVY_SHA256}  /tmp/${trivy_archive}" | sha256sum -c -; \
    tar -xzf "/tmp/${trivy_archive}" -C /tmp trivy; \
    install -m 0755 /tmp/trivy /usr/local/bin/trivy; \
    dockle_archive="dockle_${DOCKLE_VERSION}_Linux-64bit.tar.gz"; \
    if [ -f "/opt/catscan/tool-archives/${dockle_archive}" ]; then \
      cp "/opt/catscan/tool-archives/${dockle_archive}" "/tmp/${dockle_archive}"; \
    else \
      curl --fail --location --silent --show-error \
        "https://github.com/goodwithtech/dockle/releases/download/v${DOCKLE_VERSION}/${dockle_archive}" \
        --output "/tmp/${dockle_archive}"; \
    fi; \
    echo "${DOCKLE_SHA256}  /tmp/${dockle_archive}" | sha256sum -c -; \
    tar -xzf "/tmp/${dockle_archive}" -C /tmp dockle; \
    install -m 0755 /tmp/dockle /usr/local/bin/dockle; \
    helm_archive="helm-v${HELM_VERSION}-linux-amd64.tar.gz"; \
    if [ -f "/opt/catscan/tool-archives/${helm_archive}" ]; then \
      cp "/opt/catscan/tool-archives/${helm_archive}" "/tmp/${helm_archive}"; \
    else \
      curl --fail --location --silent --show-error \
        "https://get.helm.sh/${helm_archive}" \
        --output "/tmp/${helm_archive}"; \
    fi; \
    echo "${HELM_SHA256}  /tmp/${helm_archive}" | sha256sum -c -; \
    tar -xzf "/tmp/${helm_archive}" -C /tmp; \
    install -m 0755 /tmp/linux-amd64/helm /usr/local/bin/helm; \
    copa_archive="copa_${COPA_VERSION}_linux_amd64.tar.gz"; \
    if [ -f "/opt/catscan/tool-archives/${copa_archive}" ]; then \
      cp "/opt/catscan/tool-archives/${copa_archive}" "/tmp/${copa_archive}"; \
    else \
      curl --fail --location --silent --show-error \
        "https://github.com/project-copacetic/copacetic/releases/download/v${COPA_VERSION}/${copa_archive}" \
        --output "/tmp/${copa_archive}"; \
    fi; \
    echo "${COPA_SHA256}  /tmp/${copa_archive}" | sha256sum -c -; \
    tar -xzf "/tmp/${copa_archive}" -C /tmp copa; \
    install -m 0755 /tmp/copa /usr/local/bin/copa; \
    rm -rf /tmp/trivy /tmp/dockle /tmp/copa "/tmp/${trivy_archive}" "/tmp/${dockle_archive}" /tmp/linux-amd64 "/tmp/${helm_archive}" "/tmp/${copa_archive}"; \
    trivy --version; \
    dockle --version; \
    helm version --short; \
    copa --version

COPY catscan-version /usr/local/bin/catscan-version
RUN chmod 0755 /usr/local/bin/catscan-version

# Prepare the Grype database while building the image. A pre-populated archive
# in the context supports a disconnected final build; otherwise the connected
# build stage downloads a current snapshot from the configured endpoint.
COPY grype-db /opt/catscan/grype-db
COPY catscan-validate-offline-release /usr/local/bin/catscan-validate-offline-release
RUN set -eux; \
    echo "Refreshing Grype database (token=${GRYPE_DB_REFRESH})"; \
    if [ -s /opt/catscan/grype-db/grype-vuln-db.tar.zst ]; then \
      GRYPE_DB_CACHE_DIR=/opt/catscan/grype-db GRYPE_DB_AUTO_UPDATE=false grype db import /opt/catscan/grype-db/grype-vuln-db.tar.zst; \
      if [ ! -s /opt/catscan/grype-db/latest.json ]; then \
        metadata_file="$(find /opt/catscan/grype-db -type f -name metadata.json -size +0c -print -quit)"; \
        [ -n "$metadata_file" ] && cp "$metadata_file" /opt/catscan/grype-db/latest.json; \
      fi; \
    elif find /opt/catscan/grype-db -type f -name vulnerability.db -size +0c -print -quit | grep -q .; then \
      echo "Using pre-populated Grype database from the build context"; \
      if [ ! -s /opt/catscan/grype-db/latest.json ]; then \
        metadata_file="$(find /opt/catscan/grype-db -type f -name metadata.json -size +0c -print -quit)"; \
        [ -n "$metadata_file" ] && cp "$metadata_file" /opt/catscan/grype-db/latest.json; \
      fi; \
    else \
      rm -f /opt/catscan/grype-db/latest.json; \
      curl --fail --location --retry 3 --silent --show-error \
        "${GRYPE_DB_UPDATE_URL}" \
        --output /opt/catscan/grype-db/latest.json; \
      GRYPE_DB_CACHE_DIR=/opt/catscan/grype-db \
        GRYPE_DB_UPDATE_URL="${GRYPE_DB_UPDATE_URL}" \
        GRYPE_DB_AUTO_UPDATE=true \
        grype db update; \
    fi; \
    chmod 0755 /usr/local/bin/catscan-validate-offline-release; \
    /usr/local/bin/catscan-validate-offline-release

ENV CATS_SCANNER_VERSION=${CATS_SCANNER_VERSION} \
    CATS_SCANNING_ROOT=/opt/cats/scanning \
    GRYPE_DB_CACHE_DIR=/opt/catscan/grype-db \
    GRYPE_DB_UPDATE_URL=${GRYPE_DB_UPDATE_URL} \
    GRYPE_DB_AUTO_UPDATE=false \
    GRYPE_DB_REQUIRE_UPDATE_CHECK=false \
    GRYPE_DB_VALIDATE_AGE=false \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    SYFT_CHECK_FOR_APP_UPDATE=false \
    GRYPE_DB_METADATA=/opt/catscan/grype-db/latest.json

# Optional pre-populated runtime caches. Trivy configuration scans can operate
# with checks embedded in the pinned binary even when this cache is empty.
COPY trivy-cache /opt/catscan/trivy-cache
COPY helm-cache /opt/catscan/helm
RUN mkdir -p \
      /opt/catscan/trivy-cache \
      /opt/catscan/helm/cache \
      /opt/catscan/helm/config \
      /opt/catscan/helm/data \
    && chmod -R a+rwX /opt/catscan/trivy-cache /opt/catscan/helm

ENV TRIVY_CACHE_DIR=/opt/catscan/trivy-cache \
    TRIVY_SKIP_CHECK_UPDATE=true \
    HELM_CACHE_HOME=/opt/catscan/helm/cache \
    HELM_CONFIG_HOME=/opt/catscan/helm/config \
    HELM_DATA_HOME=/opt/catscan/helm/data

COPY catscan-import-grype-db /usr/local/bin/catscan-import-grype-db
COPY catscan-trivy-config /usr/local/bin/catscan-trivy-config
COPY catscan-self-test /usr/local/bin/catscan-self-test
RUN chmod 0755 \
      /usr/local/bin/catscan-import-grype-db \
      /usr/local/bin/catscan-trivy-config \
      /usr/local/bin/catscan-self-test

WORKDIR /workspace
CMD ["bash"]
