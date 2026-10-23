FROM python:3.11-slim
WORKDIR /srv
RUN pip install --no-cache-dir fastapi==0.139.0 uvicorn
COPY app.py .
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
