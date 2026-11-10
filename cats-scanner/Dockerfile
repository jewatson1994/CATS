ARG BASE_IMAGE=alpine:3.22
FROM docker/compose-bin:v2.39.4 AS worker-compose
FROM ${BASE_IMAGE} AS validation-loadbalancer
# The validation bundle is acquired only while building the image.
RUN apk add --no-cache ca-certificates python3 py3-yaml skopeo
COPY cats-scanner/certs /usr/local/share/ca-certificates
RUN update-ca-certificates
COPY cats-scanner/tool-archives /opt/catscan/tool-archives
COPY cats-scanner/build-loadbalancer-bundle.py /usr/local/bin/build-loadbalancer-bundle.py
COPY cats-scanner/build-ingress-bundle.py /usr/local/bin/build-ingress-bundle.py
RUN python3 /usr/local/bin/build-loadbalancer-bundle.py \
      /opt/catscan/tool-archives /opt/cats/validation/loadbalancer \
    && python3 /usr/local/bin/build-ingress-bundle.py \
      /opt/catscan/tool-archives /opt/cats/validation/ingress

FROM ${BASE_IMAGE}
COPY --from=validation-loadbalancer /opt/cats/validation/loadbalancer /opt/cats/validation/loadbalancer
COPY --from=validation-loadbalancer /opt/cats/validation/ingress /opt/cats/validation/ingress

ARG CATS_SCANNER_VERSION=0.1.0
ARG GRYPE_VERSION=0.98.0
ARG GRYPE_SHA256=2c8769050993a117a20859a7ced8c748f5eb827de31d88c82e1f8c175f6bfe0f
ARG SYFT_VERSION=1.31.0
ARG SYFT_SHA256=aa60fbe2a32453e7dea991c9c5c616ae1fff0c51e910419ae53bc6555bfd2ce2
ARG TRIVY_VERSION=0.69.3
ARG TRIVY_SHA256=1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75
ARG DOCKLE_VERSION=0.4.15
ARG DOCKLE_SHA256=8bfc9183d1d3d67800edb45bea4bb63ddf1d28bec5f89944075a07007d79caad
ARG HELM_VERSION=4.2.3
ARG HELM_SHA256=e9b88b4ee95b18c706839c28d3a0220e5bc470e9cd9262410c90793c45ff8b7c
ARG KIND_VERSION=0.33.0
ARG KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
ARG KUBECTL_VERSION=1.37.0
ARG KUBECTL_SHA256=6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f
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
      cats.kind.version="${KIND_VERSION}" \
      cats.kubectl.version="${KUBECTL_VERSION}" \
      cats.copa.version="${COPA_VERSION}"

RUN apk add --no-cache \
      bash \
      bubblewrap \
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
      skopeo \
      tar \
      unzip \
      util-linux \
      wget \
      yq \
      zstd

# Place one PEM-encoded enterprise CA bundle (or individual public *.crt
# files) in certs/. A bundle may contain both roots and the intermediate.
# Trust is installed before pinned tools are downloaded.
COPY cats-scanner/certs /usr/local/share/ca-certificates
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
COPY cats-scanner/tool-archives /opt/catscan/tool-archives
RUN set -eux; \
    test "$TARGETARCH" = "amd64"; \
    for tool in syft grype; do \
      if [ "$tool" = syft ]; then version="$SYFT_VERSION"; checksum="$SYFT_SHA256"; \
      else version="$GRYPE_VERSION"; checksum="$GRYPE_SHA256"; fi; \
      archive="${tool}_${version}_linux_amd64.tar.gz"; \
      if [ -f "/opt/catscan/tool-archives/${archive}" ]; then \
        cp "/opt/catscan/tool-archives/${archive}" "/tmp/${archive}"; \
      else \
        curl --fail --location --silent --show-error \
          "https://github.com/anchore/${tool}/releases/download/v${version}/${archive}" \
          --output "/tmp/${archive}"; \
      fi; \
      echo "${checksum}  /tmp/${archive}" | sha256sum -c -; \
      tar -xzf "/tmp/${archive}" -C /tmp "$tool"; \
      install -m 0755 "/tmp/$tool" "/usr/local/bin/$tool"; \
      rm "/tmp/${archive}" "/tmp/$tool"; \
    done; \
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
    kind_binary="kind-v${KIND_VERSION}-linux-amd64"; \
    if [ -f "/opt/catscan/tool-archives/${kind_binary}" ]; then \
      cp "/opt/catscan/tool-archives/${kind_binary}" "/tmp/${kind_binary}"; \
    else \
      curl --fail --location --silent --show-error \
        "https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-linux-amd64" \
        --output "/tmp/${kind_binary}"; \
    fi; \
    echo "${KIND_SHA256}  /tmp/${kind_binary}" | sha256sum -c -; \
    install -m 0755 "/tmp/${kind_binary}" /usr/local/bin/kind; \
    kubectl_binary="kubectl-v${KUBECTL_VERSION}-linux-amd64"; \
    if [ -f "/opt/catscan/tool-archives/${kubectl_binary}" ]; then \
      cp "/opt/catscan/tool-archives/${kubectl_binary}" "/tmp/${kubectl_binary}"; \
    else \
      curl --fail --location --silent --show-error \
        "https://dl.k8s.io/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
        --output "/tmp/${kubectl_binary}"; \
    fi; \
    echo "${KUBECTL_SHA256}  /tmp/${kubectl_binary}" | sha256sum -c -; \
    install -m 0755 "/tmp/${kubectl_binary}" /usr/local/bin/kubectl; \
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
    rm -rf /tmp/trivy /tmp/dockle /tmp/copa "/tmp/${trivy_archive}" "/tmp/${dockle_archive}" /tmp/linux-amd64 "/tmp/${helm_archive}" "/tmp/${kind_binary}" "/tmp/${kubectl_binary}" "/tmp/${copa_archive}"; \
    trivy --version; \
    dockle --version; \
    helm version --short; \
    kind version; \
    kubectl version --client=true; \
    copa --version

COPY cats-scanner/catscan-version /usr/local/bin/catscan-version
COPY cats-scanner/LICENSE /opt/cats/LICENSE
RUN bash -c 'if LC_ALL=C od -An -t x1 /usr/local/bin/catscan-version | grep -w 0d >/dev/null; then echo "CR byte in catscan-version" >&2; exit 1; fi; bash -n /usr/local/bin/catscan-version'
RUN chmod 0755 /usr/local/bin/catscan-version

# Prepare the Grype database while building the image. A pre-populated archive
# in the context supports a disconnected final build; otherwise the connected
# build stage downloads a current snapshot from the configured endpoint.
COPY cats-scanner/grype-db /opt/catscan/grype-db
COPY cats-scanner/catscan-validate-offline-release /usr/local/bin/catscan-validate-offline-release
RUN bash -c 'if LC_ALL=C od -An -t x1 /usr/local/bin/catscan-validate-offline-release | grep -w 0d >/dev/null; then echo "CR byte in offline validator" >&2; exit 1; fi; bash -n /usr/local/bin/catscan-validate-offline-release'
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
    find /opt/catscan/grype-db -type d -exec chmod 0755 {} +; \
    find /opt/catscan/grype-db -type f -exec chmod 0644 {} +; \
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
COPY cats-scanner/trivy-cache /opt/catscan/trivy-cache
COPY cats-scanner/helm-cache /opt/catscan/helm
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

COPY cats-scanner/catscan-import-grype-db /usr/local/bin/catscan-import-grype-db
COPY cats-scanner/catscan-trivy-config /usr/local/bin/catscan-trivy-config
COPY cats-scanner/catscan-self-test /usr/local/bin/catscan-self-test
RUN bash -c 'for f in /usr/local/bin/catscan-import-grype-db /usr/local/bin/catscan-trivy-config /usr/local/bin/catscan-self-test; do if LC_ALL=C od -An -t x1 "$f" | grep -w 0d >/dev/null; then echo "CR byte in runtime script: $f" >&2; exit 1; fi; bash -n "$f" || exit; done'
RUN chmod 0755 \
      /usr/local/bin/catscan-import-grype-db \
      /usr/local/bin/catscan-trivy-config \
      /usr/local/bin/catscan-self-test

# Shared stdlib-only offline actions are also available to standalone scans.
COPY --from=worker-compose /docker-compose /usr/local/bin/docker-compose
COPY portal/app/rendering.py portal/app/scan_runtime.py portal/app/scanner_actions.py portal/app/scanner_inputs.py /app/app/
COPY portal/app/action_supervisor.py /app/app/
COPY portal/app/scanner_errors.py /app/app/
RUN touch /app/app/__init__.py
COPY scanning-main/scripts /opt/cats/scanning/scripts
COPY deploy/verify-worker-tools.py /tmp/verify-worker-tools.py
RUN python3 /tmp/verify-worker-tools.py "${HELM_VERSION}" "${KUBECTL_VERSION}" "2.39.4" \
    && rm /tmp/verify-worker-tools.py
ENV PYTHONPATH=/app CATS_SCANNING_ROOT=/opt/cats/scanning
WORKDIR /workspace
CMD ["bash"]
