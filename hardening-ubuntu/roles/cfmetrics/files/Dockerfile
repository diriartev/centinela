FROM python:3.12-alpine
RUN adduser -D -H -u 10003 cfm
WORKDIR /app
COPY app/ /app/
RUN chmod -R a+rX,go-w /app
USER 10003:10003
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["python3", "/app/cfmetrics.py"]
