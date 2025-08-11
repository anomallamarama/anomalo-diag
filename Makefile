IMAGE ?= anomallamarama/anomalo-diag
TAG ?= $(shell git rev-parse --short HEAD)
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: build
build:
	docker buildx build \
	  --platform $(PLATFORMS) \
	  -t $(IMAGE):$(TAG) \
	  -t $(IMAGE):latest \
	  --push \
	  .

.PHONY: local
local:
	docker build -t $(IMAGE):local .