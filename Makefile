SHELL := /bin/bash

# Debian/Ubuntu keep asm/*.h under a multiarch directory. Arch does not need this:
#   make BPF2GO_CFLAGS="-I/usr/include/$(uname -m)-linux-gnu"
export BPF2GO_CFLAGS ?=

.PHONY: all deps generate build test vet myprocess clean

all: build

# Downloads github.com/cilium/ebpf (needs internet the first time).
deps:
	go mod tidy

# Compiles bpf/*.bpf.c with clang and generates the Go bindings next to each main.go.
generate: deps
	go generate ./cmd/portdrop ./cmd/procfilter

build: generate
	mkdir -p bin
	go build -o bin/portdrop ./cmd/portdrop
	go build -o bin/procfilter ./cmd/procfilter
	go build -o bin/demoserver ./cmd/demoserver

# Pure-Go tests: no root, no kernel features needed.
test:
	go test ./internal/...

vet: generate
	test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }
	go vet ./...

# A copy of curl whose process name is "myprocess" (the kernel takes the name
# from the executable's file name).
myprocess: build
	cp "$$(command -v curl)" bin/myprocess

clean:
	rm -rf bin
	rm -f cmd/*/*_bpfel.go cmd/*/*_bpfel.o
