# Centro de mando de Centinela: solo librería estándar de Python, sin privilegios
FROM python:3.12-alpine
RUN adduser -D -H -u 10002 panel
WORKDIR /app
COPY app/ /app/
RUN chmod -R a+rX,go-w /app
USER 10002:10002
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python3", "/app/panel.py"]
