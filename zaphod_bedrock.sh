#!/bin/bash

# zaphod_bedrock.sh
# One command to launch Zaphod with AWS Bedrock backend!

set -e

echo "🚀 Setting up Zaphod with AWS Bedrock..."

# Load configuration
USER_CONFIG_FILE="../config.json"
if [ ! -f "$USER_CONFIG_FILE" ]; then
    echo "❌ ERROR: ../config.json not found!"
    echo "Please create a config.json file with the following structure:"
    echo '{
    "aws_access_key_id": "YOUR_ACCESS_KEY",
    "aws_secret_access_key": "YOUR_SECRET_KEY",
    "aws_region": "YOUR_REGION",
    "bedrock_model_id": "anthropic.claude-v2",
    "api_key": "YOUR_API_KEY_FOR_SERVER_ACCESS"
}'
    exit 1
fi

# Extract configuration values
AWS_ACCESS_KEY=$(jq -r '.aws_access_key_id' "$USER_CONFIG_FILE")
AWS_SECRET_KEY=$(jq -r '.aws_secret_access_key' "$USER_CONFIG_FILE")
AWS_REGION=$(jq -r '.aws_region' "$USER_CONFIG_FILE")
BEDROCK_MODEL_ID=$(jq -r '.bedrock_model_id' "$USER_CONFIG_FILE")
API_KEY=$(jq -r '.api_key' "$USER_CONFIG_FILE")

# Verify all required values are present
if [[ -z "$AWS_ACCESS_KEY" || -z "$AWS_SECRET_KEY" || -z "$AWS_REGION" || -z "$BEDROCK_MODEL_ID" || -z "$API_KEY" ]]; then
    echo "❌ ERROR: Missing required configuration values in config.json"
    exit 1
fi

# Create server config directory if it doesn't exist
SERVER_CONFIG_DIR="./config"
mkdir -p "$SERVER_CONFIG_DIR"

# Create server config.json
SERVER_CONFIG_FILE="$SERVER_CONFIG_DIR/config.json"
echo "📝 Creating server configuration..."
cat > "$SERVER_CONFIG_FILE" << EOF
{
    "aws": {
        "access_key_id": "$AWS_ACCESS_KEY",
        "secret_access_key": "$AWS_SECRET_KEY",
        "region": "$AWS_REGION"
    },
    "bedrock": {
        "model_id": "$BEDROCK_MODEL_ID"
    },
    "api": {
        "key": "$API_KEY"
    }
}
EOF

# Secure the config file
chmod 600 "$SERVER_CONFIG_FILE"

# Verify AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI is not installed. Installing..."
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    sudo ./aws/install
    rm -rf aws awscliv2.zip
fi

# Configure AWS credentials
echo "🔐 Configuring AWS credentials..."
mkdir -p ~/.aws
cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id = $AWS_ACCESS_KEY
aws_secret_access_key = $AWS_SECRET_KEY
region = $AWS_REGION
EOF

chmod 600 ~/.aws/credentials

# Verify Python virtual environment
if [ ! -d "venv" ]; then
    echo "🐍 Setting up Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install required packages
echo "📦 Installing required packages..."
pip install -r requirements.txt

# Verify Bedrock access
echo "🔍 Verifying AWS Bedrock access..."
python3 - << EOF
import boto3
import json
import os

try:
    # Test loading the config
    with open('$SERVER_CONFIG_FILE', 'r') as f:
        config = json.load(f)
    
    # Test Bedrock connection
    bedrock = boto3.client(
        service_name='bedrock-runtime',
        region_name='$AWS_REGION',
        aws_access_key_id='$AWS_ACCESS_KEY',
        aws_secret_access_key='$AWS_SECRET_KEY'
    )
    print("✅ Successfully connected to AWS Bedrock!")
    print("✅ Server configuration verified!")
except Exception as e:
    print(f"❌ Configuration test failed: {str(e)}")
    exit(1)
EOF

echo "🌟 Starting Zaphod FastAPI server..."
echo "The server will be available at http://localhost:8000"
echo ""
echo "📝 API documentation will be available at:"
echo "- Swagger UI: http://localhost:8000/docs"
echo "- ReDoc: http://localhost:8000/redoc"
echo ""
echo "🔑 Your API key for authentication: $API_KEY"
echo ""

# Start the server using uvicorn
python -m uvicorn app.server:app --host 0.0.0.0 --port 8000 --reload