FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=5000
ENV USE_SIMULATOR=true
ENV FLASK_DEBUG=false
ENV USE_SERVICENOW_SIMULATOR=true
ENV USE_MERAKI_SIMULATOR=true
ENV AUTO_REMEDIATE=true
E