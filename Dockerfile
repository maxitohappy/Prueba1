FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY app ./app
COPY tests ./tests

# La app no corre como root: si alguien la compromete, tiene menos permisos.
RUN useradd --create-home appuser && mkdir /data && chown appuser /data
USER appuser

EXPOSE 5000
# 1 proceso: el rate limit y la clave secreta aleatoria viven en memoria.
CMD ["gunicorn", "--workers", "1", "--threads", "4", "--bind", "0.0.0.0:5000", "app:create_app()"]
