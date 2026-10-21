FROM postgres:16-alpine
RUN apk add --no-cache python3
COPY backup.py /opt/backup/backup.py
ENTRYPOINT ["python3", "/opt/backup/backup.py"]
CMD ["schedule"]
