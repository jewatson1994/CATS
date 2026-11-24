FROM python:3.12-slim
LABEL org.opencontainers.image.title="CATS runtime agent" \
      org.opencontainers.image.source="https://github.com/jewatson1994/CATS"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/cats-runtime
COPY cats_runtime/ ./cats_runtime/
RUN mkdir -p /var/lib/cats-runtime && chown 10001:10001 /var/lib/cats-runtime
USER 10001:10001
ENTRYPOINT ["python", "-m", "cats_runtime"]
CMD ["run", "--source", "kubernetes"]
