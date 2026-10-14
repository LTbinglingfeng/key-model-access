PLUGIN_NAME ?= key-model-access
VERSION ?= 0.1.3
BUILD_DIR ?= dist
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GO_LDFLAGS ?= -s -w -X main.pluginVersion=$(VERSION)

EXT_linux = so
EXT_freebsd = so
EXT_darwin = dylib
EXT_windows = dll
PLUGIN_EXT = $(or $(EXT_$(GOOS)),so)
PLUGIN_OUTPUT ?= $(BUILD_DIR)/$(PLUGIN_NAME).$(PLUGIN_EXT)
PLUGIN_HEADER = $(basename $(PLUGIN_OUTPUT)).h
ARCHIVE_NAME ?= $(PLUGIN_NAME)_$(VERSION)_$(GOOS)_$(GOARCH).zip
ARCHIVE_PATH ?= $(BUILD_DIR)/$(ARCHIVE_NAME)
CHECKSUM_PATH ?= $(ARCHIVE_PATH).sha256
CHECKSUMS_PATH ?= $(BUILD_DIR)/checksums.txt
CPA_DIR ?=

.PHONY: all build test test-web vet check package checksums install clean

all: check build

build:
	mkdir -p $(dir $(PLUGIN_OUTPUT))
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -buildmode=c-shared -ldflags "$(GO_LDFLAGS)" -o $(PLUGIN_OUTPUT) .
	rm -f $(PLUGIN_HEADER)
	@echo "built $(PLUGIN_OUTPUT)"

test:
	go test ./...

# Optional frontend behavior tests (Node.js 18+; no npm dependencies).
test-web:
	node --check web/settings.js
	node --test web/settings.test.js

vet:
	go vet ./...

check:
	gofmt -w *.go .github/scripts/*.go
	go vet ./...
	go test -race ./...

package: build
	go run ./.github/scripts/package-release.go -library "$(PLUGIN_OUTPUT)" -archive "$(ARCHIVE_PATH)" -checksum "$(CHECKSUM_PATH)"

checksums: package
	cat $(BUILD_DIR)/*.zip.sha256 | sort -k 2 > "$(CHECKSUMS_PATH)"

install: build
	@test -n "$(CPA_DIR)" || (echo "usage: make install CPA_DIR=/path/to/CLIProxyAPI"; exit 1)
	@mkdir -p "$(CPA_DIR)/plugins/$(GOOS)/$(GOARCH)"
	cp $(PLUGIN_OUTPUT) "$(CPA_DIR)/plugins/$(GOOS)/$(GOARCH)/$(PLUGIN_NAME).$(PLUGIN_EXT)"
	@echo "installed to $(CPA_DIR)/plugins/$(GOOS)/$(GOARCH)/$(PLUGIN_NAME).$(PLUGIN_EXT)"

clean:
	rm -rf $(BUILD_DIR)
