### Dockerfile
# Use a small but capable image
FROM python:3.10-slim

# Install required system packages
RUN apt update && apt install -y git gcc g++ curl && rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /app

# Copy requirements if separated (optional)
# COPY requirements.txt ./
# RUN pip install -r requirements.txt

# Install necessary Python packages
RUN pip install --no-cache-dir fastapi uvicorn transformers accelerate torch

# Copy the codebase
COPY . .

# Expose port
EXPOSE 8000

# Run the server
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
