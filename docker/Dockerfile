FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create data directories
RUN mkdir -p data/models data/logs

# Train the model at build time
RUN python -m ml.train

EXPOSE 8000

# Run the server
CMD ["python", "-m", "backend.main"]
