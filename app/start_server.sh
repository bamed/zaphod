#!/bin/bash

while true; do
    echo "[Monitor] Starting Uvicorn..."
    python3 -m uvicorn server:app --host 0.0.0.0 --port 8000 --reload

    echo "[Monitor] Uvicorn process exited. Restarting in 60 seconds..."
    sleep 60
done

