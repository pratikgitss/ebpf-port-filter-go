// Package config holds the small, pure helpers shared by both commands:
// flag validation and conversion of a process name to the kernel's comm format.
// Nothing here needs root or the kernel, so it is easy to unit test.
package config

import (
	"errors"
	"fmt"
	"strings"
)

// CommLen is the kernel's TASK_COMM_LEN: up to 15 name bytes plus a NUL.
const CommLen = 16

// MaxCommNameLen is the longest process name the kernel keeps.
const MaxCommNameLen = CommLen - 1

// ValidatePort checks that p is a usable TCP port and returns it as uint16.
func ValidatePort(p int) (uint16, error) {
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %d out of range (1-65535)", p)
	}
	return uint16(p), nil
}

// ValidateComm checks that name can be matched against a process name.
func ValidateComm(name string) error {
	if name == "" {
		return errors.New("process name must not be empty")
	}
	if strings.ContainsRune(name, 0) {
		return errors.New("process name must not contain a NUL byte")
	}
	return nil
}

// CommBytes converts name to the fixed 16-byte, NUL-padded form that
// bpf_get_current_comm() returns. Names longer than 15 bytes are cut at 15
// bytes, exactly like the kernel does, so the comparison in the eBPF program
// matches the real process.
func CommBytes(name string) [CommLen]byte {
	var out [CommLen]byte
	copy(out[:MaxCommNameLen], name) // copy stops at the shorter of the two
	return out
}
