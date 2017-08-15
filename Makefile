.PHONY: all
all: build

.PHONY: build
build: shadowgate

shadowgate: $(shell find . -iname '*.go' -print)
	CGO_ENABLED=0 godep go build github.com/ziyan/shadowgate
	objcopy --strip-all shadowgate

.PHONY: test
test: build
	godep go test ./...

.PHONY: docker
docker: test
	docker build -t ziyan/shadowgate .

.PHONY: save
save:
	godep save ./...

.PHONY: format
format:
	gofmt -l -w utils
