PATH := $(GOPATH)/bin:$(PATH)
export GO111MODULE=on

all: gen test examples

go-mod-check:
	@go help mod > /dev/null || (echo "Your go is too old, no modules. Seek help." && exit 1)

go-mod-download:
	@go mod download

deps-go: go-mod-check go-mod-download

deps: deps-go

gen: ./osquery.thrift
	mkdir -p ./gen
	thrift --gen go:package_prefix=github.com/Uptycs/basequery-go/gen/ -out ./gen ./osquery.thrift
	rm -rf gen/osquery/extension-remote gen/osquery/extension_manager-remote
	gofmt -w ./gen

examples: deps
	@mkdir -p build
	@go build -ldflags="-s -w" -o ./build ./...

test:
	@go test -race -cover ./...

clean:
	@rm -rf ./build ./gen

.PHONY: all
