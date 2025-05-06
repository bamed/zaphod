#!/bin/bash

# Exit on any error and undefined variables
set -e
set -u

# Initialize variables with default values and handle spaces in paths
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
APP_DIR="$SCRIPT_DIR"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Create logs directory if it doesn't exist
LOGS_DIR="$PROJECT_ROOT/logs"
mkdir -p "$LOGS_DIR"

CONFIG_FILE="./config/config.json"
VENV_DIR="$(pwd)/.venv"
REQUIREMENTS_FILE="./requirements.txt"
PYTHON_VERSION="3.11.8"

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

# Function to show usage
show_usage() {
    cat << EOF
Usage: $(basename "$0") [command]

Commands:
    start       Start the server (default if no command provided)
    clean       Remove virtual environment and local Python version
    force       Force reinstall of virtual environment
    help        Show this help message

Examples:
    ./$(basename "$0")          # Start server (create environment if needed)
    ./$(basename "$0") start    # Same as above
    ./$(basename "$0") clean    # Remove virtual environment
    ./$(basename "$0") force    # Force recreate environment
    ./$(basename "$0") help     # Show this help message
EOF
}

# Function to perform cleanup
cleanup() {
    log_info "Starting cleanup..."
    
    # Deactivate virtual environment if it's active
    if [ -n "${VIRTUAL_ENV:-}" ]; then
        log_info "Deactivating virtual environment..."
        deactivate 2>/dev/null || true
    fi

    # Remove virtual environment
    if [ -d "$VENV_DIR" ]; then
        log_info "Removing virtual environment directory..."
        rm -rf "$VENV_DIR"
    fi

    # Remove pyenv local version
    if [ -f .python-version ]; then
        log_info "Removing local Python version setting..."
        rm -f .python-version
    fi

    # Remove pip cache
    if [ -d "$HOME/.cache/pip" ]; then
        log_info "Removing pip cache..."
        rm -rf "$HOME/.cache/pip"
    fi

    # Remove __pycache__ directories
    log_info "Removing Python cache directories..."
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true

    log_info "Cleanup completed successfully!"
}

# Function to install pyenv on macOS
install_pyenv_macos() {
    if ! command -v brew &> /dev/null; then
        log_error "Homebrew is required but not installed. Please install Homebrew first:"
        log_error "Visit https://brew.sh for installation instructions"
        exit 1
    fi

    log_info "Installing pyenv via Homebrew..."
    if ! brew install pyenv; then
        log_error "Failed to install pyenv"
        exit 1
    fi

    # Set up pyenv in shell
    log_info "Setting up pyenv environment..."
    echo 'eval "$(pyenv init --path)"' >> ~/.zshrc
    echo 'eval "$(pyenv init -)"' >> ~/.zshrc
    
    # Also add to bash profile for compatibility
    echo 'eval "$(pyenv init --path)"' >> ~/.bash_profile
    echo 'eval "$(pyenv init -)"' >> ~/.bash_profile

    # Load pyenv into current shell
    eval "$(pyenv init --path)"
    eval "$(pyenv init -)"
}

# Function to set up Python with pyenv
setup_python_with_pyenv() {
    # Install build dependencies for Python
    log_info "Installing Python build dependencies..."
    brew install openssl readline sqlite3 xz zlib tcl-tk

    # Install specific Python version with pyenv
    log_info "Installing Python $PYTHON_VERSION with pyenv..."
    if ! pyenv install -s "$PYTHON_VERSION"; then
        log_error "Failed to install Python $PYTHON_VERSION"
        exit 1
    fi

    # Set local Python version for this directory
    log_info "Setting local Python version to $PYTHON_VERSION..."
    if ! pyenv local "$PYTHON_VERSION"; then
        log_error "Failed to set local Python version"
        exit 1
    fi
}

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    log_error "This script is currently configured for macOS only"
    exit 1
fi

# Check for pyenv and install if needed
if ! command -v pyenv &> /dev/null; then
    log_info "pyenv not found. Installing..."
    install_pyenv_macos
    
    # Ensure pyenv is loaded in current shell
    eval "$(pyenv init --path)"
    eval "$(pyenv init -)"
fi

# Setup Python with pyenv
setup_python_with_pyenv

# Function to check if virtual environment is valid
check_venv() {
    if [ ! -d "$VENV_DIR" ]; then
        log_warning "Virtual environment directory not found: $VENV_DIR"
        return 1
    fi

    if [ ! -f "$VENV_DIR/bin/activate" ]; then
        log_warning "Activate script not found in virtual environment"
        return 1
    fi

    VENV_PYTHON_VERSION=$("$VENV_DIR/bin/python3" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if [[ "$VENV_PYTHON_VERSION" != "3.11" ]]; then
        log_warning "Virtual environment Python version is $VENV_PYTHON_VERSION, expected 3.11"
        return 1
    fi

    return 0
}

# Function to check if required packages are installed
check_packages() {
    if ! "$VENV_DIR/bin/pip" freeze | grep -q "torch=="; then
        log_warning "PyTorch is not installed in the virtual environment"
        return 1
    fi

    if [ -f "$REQUIREMENTS_FILE" ]; then
        MISSING_PACKAGES=$("$VENV_DIR/bin/pip3" list --format=freeze | grep -v -f "$REQUIREMENTS_FILE")
        if [ -n "$MISSING_PACKAGES" ]; then
            log_warning "Some required packages are not installed:"
            echo "$MISSING_PACKAGES"
            return 1
        fi
    else
        log_error "requirements.txt not found at $REQUIREMENTS_FILE"
        return 1
    fi

    return 0
}

# Function to perform full setup
setup_environment() {
    # If force flag is set and virtual environment exists, remove it first
    if [ "${FORCE_REINSTALL:-false}" = true ] && [ -d "$VENV_DIR" ]; then
        log_info "Force reinstall requested. Cleaning up existing environment..."
        cleanup
    fi

    log_info "Starting environment setup..."

    # Create new virtual environment if it doesn't exist
    if [ ! -d "$VENV_DIR" ]; then
        log_info "Creating virtual environment..."
        if ! "$(pyenv which python3)" -m venv "$VENV_DIR"; then
            log_error "Failed to create virtual environment"
            exit 1
        fi
    fi

    # Source the virtual environment with error handling
    if ! source "$VENV_DIR/bin/activate"; then
        log_error "Failed to activate virtual environment"
        exit 1
    fi

    # Verify virtual environment activation and Python version
    VENV_PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if [[ "$VENV_PYTHON_VERSION" != "3.11" ]]; then
        log_error "Virtual environment Python version is $VENV_PYTHON_VERSION, expected 3.11"
        log_error "Please remove the .venv directory and try again"
        exit 1
    fi

    # Upgrade pip first
    log_info "Upgrading pip..."
    if ! python3 -m pip install --upgrade pip; then
        log_error "Failed to upgrade pip"
        exit 1
    fi

    # Install PyTorch CPU version first (required for auto-gptq)
    #log_info "Installing PyTorch (CPU version)..."
    #if ! python3 -m pip install torch==2.1.0 --index-url https://download.pytorch.org/whl/cpu --retries 5 --timeout 120 --no-cache-dir; then
    #    log_error "Failed to install PyTorch"
    #    exit 1
    #fi

    # Verify PyTorch installation
    #log_info "Verifying PyTorch installation..."
    #if ! python3 -c "import torch; print(f'PyTorch {torch.__version__} installed successfully')" ; then
    #    log_error "PyTorch installation verification failed"
    #    exit 1
    #fi

    # Install required packages excluding torch (which is already installed)
    if [ -f "$REQUIREMENTS_FILE" ]; then
        log_info "Installing requirements..."
        # Create a temporary requirements file without the torch line
        TMP_REQUIREMENTS=$(mktemp)
        grep -v "^torch==" "$REQUIREMENTS_FILE" > "$TMP_REQUIREMENTS"
        
        if ! python3 -m pip install -r "$TMP_REQUIREMENTS" --retries 10 --timeout 120 --no-cache-dir; then
            log_error "Failed to install requirements"
            rm "$TMP_REQUIREMENTS"
            exit 1
        fi
        rm "$TMP_REQUIREMENTS"
    else
        log_error "requirements.txt not found at $REQUIREMENTS_FILE"
        exit 1
    fi

    # Set PYTHONPATH to project root
    export PYTHONPATH="$(pwd):${PYTHONPATH:-}"
}

# Function to start the server
start_server() {
    # Check if the app directory and server.py exist
    if  [ ! -f "./server.py" ]; then
        log_error "./server.py not found"
        exit 1
    fi

    export PYTHONPATH="$(pwd):${PYTHONPATH:-}"

    # Run FastAPI server using python
    log_info "Starting FastAPI server..."
    exec python3 -m uvicorn server:app --reload --host 0.0.0.0 --port 8000
}

# Main script logic
main() {
    # Process commands
    case "${1:-start}" in
        start)
            # Check if virtual environment exists and is properly set up
            if ! check_venv; then
                log_info "No valid virtual environment found. Starting setup..."
                setup_environment
            else
                log_info "Found existing virtual environment"
                source "$VENV_DIR/bin/activate"
                
                # Check if all required packages are installed
                if ! check_packages; then
                    log_warning "Some required packages are missing. Running setup..."
                    setup_environment
                fi
            fi
            # Start the server
            start_server
            ;;
            
        clean)
            cleanup
            ;;
            
        force)
            export FORCE_REINSTALL=true
            if ! check_venv || ! check_packages; then
                log_info "Starting forced setup..."
                setup_environment
            fi
            start_server
            ;;
            
        help)
            show_usage
            exit 0
            ;;
            
        *)
            log_error "Unknown command: ${1}"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "${@:-}"
brew doctor
