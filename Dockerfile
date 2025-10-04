FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps for tesseract/pdfplumber optional features (comment out if not needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    tesseract-ocr \
    libjpeg62-turbo-dev \
    zlib1g-dev \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . /app

# Install ghostlight as editable CLI
RUN python -m pip install -e .

ENTRYPOINT ["ghostlight"]
CMD ["--help"]


