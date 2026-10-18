FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8000 \
    AQUAGUARD_DB=/app/data/aquaguard.db

WORKDIR /app
COPY main.py README.md ./
COPY static ./static
RUN useradd --system --create-home appuser && mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
CMD ["python", "main.py"]
