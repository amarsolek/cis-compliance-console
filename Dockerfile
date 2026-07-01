FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=5000
ENV USE_SIMULATOR=true
ENV USE_SERVICENOW_SIMULATOR=true
ENV USE_MERAKI_SIMULATOR=true
ENV AUTO_REMEDIATE=true
ENV ENABLE_SCHEDULER=false
ENV FLASK_DEBUG=false

EXPOSE 5000

CMD ["gunicorn", "server:app", "--bind", "0.0.0.0:5000", "--workers", "2"]
