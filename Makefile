.PHONY: build test lint clean install run

BINARY_NAME := kikipus
GO := go
GOFLAGS := -trimpath
LDFLAGS := -ldflags="-s -w -X github.com/mauropm/kikipus/internal/cli.version=0.1.0"

build:
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_NAME) ./cmd/kikipus/

test:
	$(GO) test -v -race -cover ./...

vet:
	$(GO) vet ./...

lint: vet
	@if command -v golangci-lint > /dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, running go vet only"; \
		$(GO) vet ./...; \
	fi

clean:
	rm -f $(BINARY_NAME)

install: build
	cp $(BINARY_NAME) $(GOPATH)/bin/$(BINARY_NAME)

run: build
	./$(BINARY_NAME)

snapshot: build
	./$(BINARY_NAME) snapshot

diff: build
	./$(BINARY_NAME) diff

report: build
	./$(BINARY_NAME) report

graph: build
	./$(BINARY_NAME) graph

# Development helpers
fmt:
	$(GO) fmt ./...

tidy:
	$(GO) mod tidy

deps:
	$(GO) mod download