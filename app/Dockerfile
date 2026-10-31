# Versioning
FROM python:3.15-slim

# Config
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV APP_ENV=production
ENV HOST=0.0.0.0

WORKDIR /app

# Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create user
RUN useradd --create-home --uid 10001 user1
# Copy of the app
COPY app.py .
COPY uploads/ ./uploads/
# Rights of user1
RUN chown -R user1:user1 /app
USER user1

EXPOSE 5000

# Health of the app
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3)" || exit 1

#Star of app
CMD ["python", "app.py"]
