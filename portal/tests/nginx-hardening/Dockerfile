# Explicit, opt-in derivative of the retained package-patched nginx image.
# Keep all inherited image layers and history; scanner findings remain evidence.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG BASE_IMAGE
USER root
RUN case "$BASE_IMAGE" in *@sha256:*) ;; *) exit 1 ;; esac \
    && base_digest="${BASE_IMAGE##*@sha256:}" \
    && test "${#base_digest}" -eq 64 \
    && case "$base_digest" in *[!0-9a-f]*) exit 1 ;; esac \
    && test "$(id -u nginx)" = 101 \
    && test "$(id -g nginx)" = 101 \
    && command -v wget >/dev/null \
    && test -s /usr/share/nginx/html/index.html
COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/conf.d/default.conf
LABEL org.opencontainers.image.base.name="${BASE_IMAGE}" \
      io.cats.nginx-hardening.recipe="v1" \
      io.cats.qualification="Explicit nginx runtime hardening; inherited scan evidence retained"
USER 101:101
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=2 \
    CMD wget -q -T 2 -O /dev/null http://127.0.0.1:8080/ || exit 1
STOPSIGNAL SIGQUIT
ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
