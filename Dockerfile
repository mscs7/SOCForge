FROM python:3.12-slim
WORKDIR /opt/socforge
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY examples ./examples
EXPOSE 8080
ENV SOCFORGE_DB=/data/socforge.db
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
