.PHONY: proto test build

proto:
	bash scripts/gen-proto.sh

build:
	go build ./...

test: build
	go test ./...
	go test -race ./internal/node/...
