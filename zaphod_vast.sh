#!/bin/bash

# zaphod_launch.sh
# One command to launch Zaphod in Vast.ai!

set -e

echo "🔎 Searching for the cheapest suitable GPU offer on Vast.ai..."

# Load API key
CONFIG_FILE="./app/config/config.json"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ ERROR: app/config/config.json not found!"
    exit 1
fi
VASTAI_API_KEY=$(jq -r '.vastai_api_key' "$CONFIG_FILE")

# Search for matching offers
OFFER_ID=$(vastai search offers "dph<0.50 gpu_ram>24 reliability>0.95 direct_port_count>1 geolocation=US rentable=True inet_down>100 num_gpus=1 cuda_vers>=12 dlperf>10 gpu_name in [A100,H100,H200,A40,A30,A16,A10g,A10,L40,L4,Tesla]" | sort -nk10 | head -2 | tail -1 | awk '{print $1}')

if [ -z "$OFFER_ID" ]; then
    echo "❌ No suitable offers found."
    exit 1
fi

echo "✅ Selected offer ID: $OFFER_ID"

# Create the instance
echo "🚀 Creating Vast.ai instance..."
INSTANCE_JSON=$(vastai create instance "$OFFER_ID" \
    --image "bamed/zaphod:latest" \
    --env '-p 8000:8000' \
    --disk 40 \
    --api-key $VASTAI_API_KEY \
    --ssh)

echo $INSTANCE_JSON
CONTRACT_ID=$(echo "$INSTANCE_JSON" | jq -r '.new_contract.id')

if [ -z "$CONTRACT_ID" ]; then
    echo "❌ Failed to create instance."
    exit 1
fi

echo "🛠 Waiting for instance $CONTRACT_ID to be ready..."

# Wait until the instance is "running"
while true; do
    STATUS=$(vastai show instance $CONTRACT_ID --api-key $VASTAI_API_KEY | jq -r '.instances[0].actual_status')
    if [ "$STATUS" == "running" ]; then
        echo "✅ Instance is running!"
        break
    fi
    echo "⌛ Still starting up... checking again in 10s..."
    sleep 10
done

# Get Public IP
PUBLIC_IP=$(vastai show instance $CONTRACT_ID --api-key $VASTAI_API_KEY | jq -r '.instances[0].public_ipaddr')
SSH_PORT=$(vastai show instance $CONTRACT_ID --api-key $VASTAI_API_KEY | jq -r '.instances[0].ssh_port')

echo "🔗 SSH is almost ready at $PUBLIC_IP:$SSH_PORT..."

# Wait for SSH to be available
while ! nc -z $PUBLIC_IP $SSH_PORT; do   
    echo "⌛ Waiting for SSH to come online..."
    sleep 5
done

echo ""
echo "🎯 SSH Ready! Use:"
echo ""
echo "ssh -p $SSH_PORT root@$PUBLIC_IP"
echo ""

# Monitor logs for FastAPI
echo "🔍 Watching for FastAPI to start..."

while true; do
    if nc -z $PUBLIC_IP 8000; then
        echo "✅ FastAPI Server Detected!"
        echo ""
        echo "🌐 Open your browser to:"
        echo "http://$PUBLIC_IP:8000/docs"
        echo ""
        break
    fi
    echo "⌛ FastAPI not up yet... retrying in 5s..."
    sleep 5
done

echo "🚀 All Systems Go!"

