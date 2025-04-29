# Start from an official lightweight CUDA image
FROM nvidia/cuda:12.1.1-runtime-ubuntu22.04

# Environment setup
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt update && apt install -y \
    python3.10 python3-pip git curl nano wget vim \
    && rm -rf /var/lib/apt/lists/*

# Install basic Python packages
RUN pip3 install --upgrade pip

# Install Hugging Face libraries
RUN pip3 install --no-cache-dir \
    torch==2.2.2+cu121 torchvision==0.17.2+cu121 torchaudio==2.2.2+cu121 --index-url https://download.pytorch.org/whl/cu121 

RUN pip3 install --no-cache-dir transformers accelerate fastapi uvicorn 

# Create user and group
RUN addgroup --system zaphod && adduser --system --ingroup zaphod zaphod

# Create workspace directory
WORKDIR /workspace

# Copy local files into the container
COPY requirements.txt .

RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

# Set model cache directory (you can change this if needed)
ENV HF_HOME=/workspace/model_cache
RUN mkdir -p $HF_HOME

# Fix ownership (VERY IMPORTANT)
RUN chown -R zaphod:zaphod /workspace
RUN chmod 750 /workspace/app/start_server.sh

# Example: set directories and files minimal permissions
RUN find /workspace -type d -exec chmod 755 {} \; \
 && find /workspace -type f -exec chmod 644 {} \;

# Switch user
USER zaphod

# Expose port for FastAPI
EXPOSE 8000

# Start the server
CMD ["/workspace/app/start_server.sh"]
