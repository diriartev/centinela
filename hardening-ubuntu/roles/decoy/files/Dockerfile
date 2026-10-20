# Web señuelo de Centinela: solo librería estándar de Python, usuario sin privilegios
FROM python:3.12-alpine
RUN adduser -D -H -u 10001 web
WORKDIR /app
COPY app/ /app/
RUN chmod -R a+rX,go-w /app
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DECOY_LOG=/log/decoy.json
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/robots.txt',timeout=4)"
CMD ["python3", "/app/decoy.py"]
