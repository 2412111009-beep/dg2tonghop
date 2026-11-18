FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LABBOOK_DATA=/data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -r -u 1000 labbook && mkdir -p /data && chown labbook /data
USER labbook
VOLUME /data
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:5000/login', timeout=3)"
# SQLite ghi một nơi: 1 worker + nhiều thread để tránh tranh chấp khóa
CMD ["gunicorn", "-w", "1", "--threads", "4", "-b", "0.0.0.0:5000", "app:app"]
