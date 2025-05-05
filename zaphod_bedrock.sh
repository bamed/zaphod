#!/bin/bash

# Exit on any error and undefined variables
set -e
set -u

# Initialize variables with default values and handle spaces in paths
CONFIG_FILE="./config.json"
VENV_DIR="./.venv"
REQUIREMENTS_FILE="./requirements.txt"

# Function to log errors
log_error() {
    echo "ERROR: $1" >&2
}

# Function to log info
log_info() {
    echo "INFO: $1"
}

# Function to log warnings
log_warning() {
    echo "WARNING: $1"
}

# Check if python3 is available
if ! command -v python3 &> /dev/null; then
    log_error "Python 3 is not installed or not in PATH"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if (( $(echo "$PYTHON_VERSION 3.11" | awk '{if ($1 > $2) print 1; else print 0;}') )); then
    log_error "Python version $PYTHON_VERSION is not fully supported by PyTorch yet."
    log_error "Please use Python 3.11.x for full compatibility."
    log_error "You can:"
    log_error "1. Install Python 3.11.x from python.org"
    log_error "2. Create a new virtual environment with Python 3.11"
    log_error "3. Run this script again with the new Python version"
    exit 1
fi

# Create and activate virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    log_info "Creating virtual environment..."
    if ! python3 -m venv "$VENV_DIR"; then
        log_error "Failed to create virtual environment"
        exit 1
    fi
fi

# Source the virtual environment with error handling
if ! source "$VENV_DIR/bin/activate"; then
    log_error "Failed to activate virtual environment"
    exit 1
fi

# Verify virtual environment activation
if [[ "$VIRTUAL_ENV" != "$(pwd)/.venv" ]]; then
    log_error "Virtual environment not properly activated"
    exit 1
fi

# Upgrade pip3 first
log_info "Upgrading pip3..."
if ! python3 -m pip install --upgrade pip; then
    log_error "Failed to upgrade pip3"
    exit 1
fi

# Install PyTorch CPU version first (required for auto-gptq)
log_info "Installing PyTorch (CPU version)..."
if ! python3 -m pip install torch==2.1.0 --index-url https://download.pytorch.org/whl/cpu; then
    log_error "Failed to install PyTorch"
    log_error "This might be due to Python version incompatibility"
    exit 1
fi

# Rest of the script remains the same...