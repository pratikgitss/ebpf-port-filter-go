//go:build tools

// Package tools pins build-time dependencies so `go mod tidy` keeps them.
package tools

import _ "github.com/cilium/ebpf/cmd/bpf2go"
