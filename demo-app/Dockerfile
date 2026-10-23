# INTENTIONALLY VULNERABLE demo target image.
# PLANTED WEAKNESSES (for container scanners): it runs as root and has no HEALTHCHECK.
FROM python:3.11-slim
WORKDIR /srv
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
EXPOSE 5000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5000"]
