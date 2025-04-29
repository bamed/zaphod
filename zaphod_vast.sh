#!/bin/bash

# zaphod_launch.sh
# One command to launch Zaphod in Vast.ai!

set -e

echo "🔎 Searching for the cheapest suitable GPU offer on Vast.ai..."

# Load API key
CONFIG_FILE="../config.json"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ ERROR: ../config.json not found!"
    exit 1
fi
VASTAI_API_KEY=$(jq -r '.vastai_api_key' "$CONFIG_FILE")
HF_TOKEN=$(jq -r '.hf_token' "$CONFIG_FILE")

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
    --onstart-cmd "mkdir -p /workspace/config && echo '{\"hf_token\": \"$HF_TOKEN\"}' > /workspace/config/config.json && cd /workspace/app && /workspace/app/start_server.sh" \
    --disk 40 \
    --api-key $VASTAI_API_KEY \
    --ssh)

echo $INSTANCE_JSON
if [ -n "$ZSH_VERSION" ]; then
    # running in zsh
    CONTRACT_ID=$(echo "${(L)INSTANCE_JSON}" | grep -o '{.*}'| sed "s/'/\"/g"| jq -r '.new_contract')
elif [ -n "$BASH_VERSION" ]; then
    # running in bash
    CONTRACT_ID=$(echo "${INSTANCE_JSON,,}" | grep -o '{.*}'| sed "s/'/\"/g"| jq -r '.new_contract')
else
    echo "Unsupported shell. Please run with bash or zsh."
    exit 1
fi


echo $CONTRACT_ID

if [ -z "$CONTRACT_ID" ]; then
    echo "❌ Failed to create instance."
    exit 1
fi

echo "🛠 Waiting for instance $CONTRACT_ID to be ready..."

# Wait until the instance is "running"
while true; do
    STATUS=$(vastai show instance $CONTRACT_ID --api-key $VASTAI_API_KEY --raw | jq -r '.actual_status')
#    STATUS=$(vastai show instance $CONTRACT_ID --api-key $VASTAI_API_KEY )
#    echo $STATUS
#    STATUS=$(echo $STATUS | awk '{print $27}' )
    if [ "$STATUS" == "running" ]; then
        echo "✅ Instance is running!"
        break
    fi
    echo "⌛ Still starting up... checking again in 10s..."
    sleep 10
done

# Get Public IP
PUBLIC_IP=$(vastai show instance $CONTRACT_ID --api-key $VASTAI_API_KEY --raw | jq -r '.ssh_host')
SSH_PORT=$(vastai show instance $CONTRACT_ID --api-key $VASTAI_API_KEY --raw | jq -r '.ssh_port')

echo "🔗 SSH is almost ready at $PUBLIC_IP:$SSH_PORT..."

# Wait for SSH to be available
echo ""
echo "ssh -p $SSH_PORT -i ~/.ssh/vast.pem root@$PUBLIC_IP -L 8000:localhost:8000"
echo ""

# Monitor logs for FastAPI
echo "🔍 You still need to ssh in and setup your config.json"

