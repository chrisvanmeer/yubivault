.PHONY: all build run test test-race lint fmt css clean tidy

BINARY := yubivault

all: fmt lint test build

build:
	go build -o $(BINARY) .

run:
	go run .

test:
	go test ./...

test-race:
	go test -race ./...

lint:
	gofmt -l .
	go vet ./...
	golangci-lint run

fmt:
	gofmt -w .

css:
	npm install --silent
	npx tailwindcss -i input.css -o static/tailwind.css --minify

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)
