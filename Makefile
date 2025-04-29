# Zaphod Makefile
# Build, tag, and push your Docker image with ease

# Configurable Variables
#REGISTRY ?= docker.io
USER ?= bamed
IMAGE ?= zaphod
VERSION ?= $(shell date +%Y%m%d%H%M%S)

# Full Image Name
#IMAGE_NAME = $(REGISTRY)/$(USER)/$(IMAGE)
IMAGE_NAME = $(USER)/$(IMAGE)

# Color codes
GREEN=\033[0;32m
RED=\033[0;31m
#NC=\033[0m

# Default target
all: help

## Build the docker image
build:
	@echo -e "$(GREEN)[*] Building Docker image $(IMAGE_NAME):$(VERSION)"
	docker build -t $(IMAGE_NAME):$(VERSION) .
	docker tag $(IMAGE_NAME):$(VERSION) $(IMAGE_NAME):latest
	@echo -e "$(GREEN)[+] Build complete: $(IMAGE_NAME):$(VERSION)"

## Push the docker image to Docker Hub
push: build
	@echo -e "$(GREEN)[*] Pushing $(IMAGE_NAME):$(VERSION) and latest to Docker Hub"
	docker push $(IMAGE_NAME):$(VERSION)
	docker push $(IMAGE_NAME):latest
	@echo -e "$(GREEN)[+] Push complete!"

## Clean dangling docker images
clean:
	@echo -e "$(GREEN)[*] Cleaning up dangling Docker images..."
	docker image prune -f
	@echo -e "$(GREEN)[+] Cleanup complete!"

## Show available Makefile targets
help:
	@echo "Zaphod Management Makefile:"
	@echo ""
	@echo "  make build        Build the Docker image (tagged with version and latest)"
	@echo "  make push         Build and push the Docker image to Docker Hub"
	@echo "  make clean        Remove dangling Docker images"
	@echo "  make help         Show this help message"
	@echo ""
	@echo "Variables you can override (defaults in parentheses):"
	@echo "  USER       (bamed)"
	@echo "  IMAGE      (zaphod)"
	@echo "  VERSION    (current timestamp)"
	@echo ""
	@echo "Example to build a specific version:"
	@echo "  make build VERSION=1.0.0"

