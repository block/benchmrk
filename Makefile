.PHONY: build test lint clean migrate

build:
	go build -o bin/benchmrk ./cmd/benchmrk

test:
	go test -race -v ./...

lint:
	go vet ./...
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck ./...; fi

clean:
	rm -rf bin/
	go clean

migrate:
	@echo "Run migrations (not yet implemented)"
