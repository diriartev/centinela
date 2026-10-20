# Vigía de alertas de Centinela: solo librería estándar, usuario sin privilegios
FROM python:3.12-alpine
RUN adduser -D -H -u 10004 vigia
WORKDIR /app
COPY app/ /app/
RUN chmod -R a+rX,go-w /app
USER 10004:10004
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["python3", "/app/vigia.py"]
