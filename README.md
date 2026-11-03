# eBPF packet-drop demos in G# eBPF packet-drop demos in Go

Two small eBPF programs with Go loaders (using [cilium/ebpf](https://github.com/cilium/ebpf)):

| Program | What it does | Hook |
| --- | --- | --- |
| `portdrop` | Drops incoming TCP packets on a port (default **4040**). The port is configurable from userspace, also while it runs. | XDP |
| `procfilter` | Lets one named process (default `myprocess`) connect to **one** TCP port only (default **4040**). Every other port is rejected for that process; all other processes are unaffected. | `cgroup/connect4` + `cgroup/connect6` |

**Demo video:** <ADD YOUR VIDEO LINK HERE>

**Tested on:** Arch Linux, kernel `<OUTPUT OF uname -r>`, Go 1.27.3, clang 23.1.4. Both programs were run
against IPv4 (`127.0.0.1`) and IPv6 (`::1`) on the loopback interface.

```
bpf/portdrop.bpf.c     XDP program (C)
bpf/procfilter.bpf.c   cgroup connect hooks (C)
cmd/portdrop/          Go loader for problem 1
cmd/procfilter/        Go loader for problem 2
cmd/demoserver/        tiny HTTP server used for the demos
internal/config/       pure Go helpers (flag validation, process-name handling) + tests
tools.go               keeps the bpf2go build tool in go.mod
Makefile               build, test, vet, clean
```

## Prerequisites (Arch Linux)

```bash
sudo pacman -S --needed go clang llvm libbpf linux-headers make curl
ls /sys/kernel/btf/vmlinux          # should exist
stat -fc %T /sys/fs/cgroup          # should print cgroup2fs (needed by procfilter)
```

Go (the minimum version is the `go` line in `go.mod`) and internet access for the first build (it
downloads `github.com/cilium/ebpf`).
Loading eBPF programs needs root (or `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_ADMIN`).

## Build

```bash
make            # go mod tidy, bpf2go (compiles the C), go build -> ./bin/
make test       # unit tests, no root needed
make myprocess  # bin/myprocess = a copy of curl whose process name is "myprocess"
```

If `make` complains about `asm/types.h` (Debian/Ubuntu style systems), run
`make BPF2GO_CFLAGS="-I/usr/include/$(uname -m)-linux-gnu"`.

## Problem 1: drop TCP packets on a port

Terminal A: servers on three ports.

```bash
./bin/demoserver 4040 5050 8080
```

Terminal B: everything works before the program is loaded.

```bash
curl --max-time 3 http://127.0.0.1:4040     # hello from port 4040
curl --max-time 3 http://127.0.0.1:8080     # hello from port 8080
```

Terminal C: load the program (attached to the loopback interface by default).

```bash
sudo ./bin/portdrop --iface lo --port 4040
```

Terminal B again:

```bash
curl --max-time 3 http://127.0.0.1:4040     # curl: (28) Connection timed out ...
curl --max-time 3 http://127.0.0.1:8080     # still works
```

Change the port **while it is running** (Terminal B):

```bash
sudo ./bin/portdrop set-port 8080
curl --max-time 3 http://127.0.0.1:4040     # works again
curl --max-time 3 http://127.0.0.1:8080     # now dropped
```

Press Ctrl+C in Terminal C: the program detaches, prints the number of dropped packets, and
both ports work again.

```bash
curl --max-time 3 http://127.0.0.1:4040     # works
curl --max-time 3 http://127.0.0.1:8080     # works
sudo ls /sys/fs/bpf/portdrop                # No such file or directory (the pinned map is removed)
```

Flags: `--iface` (default `lo`), `--port` (default `4040`), `--generic` (force XDP generic mode;
otherwise native mode is tried first and generic mode is the fallback).

> A dropped SYN packet gets no reply at all, so the client sees a **timeout**, not "connection refused".

**IPv6 check (optional).** The demo server listens on all addresses, so it also answers on `::1`.
With `portdrop` loaded on port 4040:

```bash
curl -g --max-time 3 'http://[::1]:4040'    # dropped (timeout)
curl -g --max-time 3 'http://[::1]:8080'    # still works
```

## Problem 2: allow only one port for one process

Terminal A: the same servers as above (`./bin/demoserver 4040 5050 8080`).

Terminal C: load the filter for the process named `myprocess`. `bin/myprocess` was created by
`make myprocess` above.

```bash
sudo ./bin/procfilter --comm myprocess --port 4040
```

Terminal B:

```bash
./bin/myprocess --max-time 3 -sS http://127.0.0.1:4040   # allowed: hello from port 4040
./bin/myprocess --max-time 3 -sS http://127.0.0.1:5050   # rejected at once: curl: (7) Failed to connect ...
./bin/myprocess --max-time 3 -sS http://127.0.0.1:8080   # rejected too: every other port is blocked
curl --max-time 3 -sS http://127.0.0.1:5050              # a different process: still works
```

Press Ctrl+C in Terminal C to detach; `myprocess` can reach 5050 again:

```bash
./bin/myprocess --max-time 3 -sS http://127.0.0.1:5050   # hello from port 5050
```

Flags: `--comm` (default `myprocess`), `--port` (default `4040`), `--cgroup` (default `/sys/fs/cgroup`).
The process name is the executable's file name, cut to 15 bytes (a kernel limit). That is why the demo
copies `curl` to a file called `myprocess`.

**IPv6 check (optional).** With `procfilter` loaded:

```bash
./bin/myprocess -g --max-time 3 -sS 'http://[::1]:4040'   # allowed
./bin/myprocess -g --max-time 3 -sS 'http://[::1]:5050'   # rejected at once
curl -g --max-time 3 -sS 'http://[::1]:5050'              # a different process: still works
```

## How it works

**Why XDP for problem 1.** XDP runs on every incoming packet before the rest of the network stack.
The C program parses Ethernet, then IPv4 or IPv6, then TCP, checking every pointer against
`data_end` (the verifier requires this). If the TCP destination port equals the configured port it
returns `XDP_DROP`, otherwise `XDP_PASS`.

**How the port is configurable.** The port lives in a BPF array map (`config[0]`). The Go loader writes
it with `Map.Put`. `portdrop` also pins that map under `/sys/fs/bpf/portdrop/`, so
`portdrop set-port N` can open it and change the value of the running program, with no reload.
The drop counter is a per-CPU map that Go sums and prints.

**Why not XDP for problem 2.** A packet seen by XDP (or TC) is not tied to a local process yet, so
there is no process name to match. `cgroup/connect4` and `cgroup/connect6` run inside the process's own
`connect()` system call: `bpf_get_current_comm()` returns that process's name, and returning `0`
makes `connect()` fail with a permission error before any packet is sent. The program compares the name
(a bounded 16-byte loop) with the one Go stored in a map. If it matches and the destination port is not the
allowed one, the connection is rejected. Both IPv4 and IPv6 hooks are attached so the process cannot
bypass the rule through IPv6. The programs are attached to the root cgroup, so they cover every process;
only the named one is ever restricted.

## Limitations

- `portdrop` handles IPv4 and IPv6 (TCP directly after the IPv6 header, no extension headers) on
  **ingress** of one interface. Use `--iface` for other interfaces; outgoing traffic is not filtered.
- Matching on process name is weak: any process can be renamed (copy the binary, or `prctl(PR_SET_NAME)`),
  and two different programs may share a name. The kernel keeps only 15 bytes of the name.
- `procfilter` blocks at `connect()` time: it does not cut connections that are already established,
  and does not cover servers (`accept`) or unconnected UDP. Only TCP sockets are filtered.
- Matching uses the name of the calling thread (`comm`), which for normal programs equals the executable
  name.
- If the maps are not configured yet, `procfilter` lets traffic through instead of breaking the system
  (the Go loader always configures them before attaching).
- Attaching to the root cgroup affects every matching process on the machine; use `--cgroup` to
  restrict it to one cgroup.
- Needs root and a kernel with BTF and cgroup v2; XDP on `lo` runs in generic mode.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `operation not permitted` when loading | run with `sudo` |
| `cgroup path ... is not a directory` | cgroup v2 is not mounted at `/sys/fs/cgroup`; pass `--cgroup` |
| nothing is dropped | test with `127.0.0.1` (or `[::1]` with `curl -g`), not `localhost`; while `portdrop` runs, `ip link show lo` should show an `xdp` or `xdpgeneric` entry |
| `set-port` says it cannot open the pinned map | `portdrop` is not running, or `/sys/fs/bpf` is not a bpffs mount |
| `address already in use` when starting `demoserver` | an old `demoserver` is still running: `pkill demoserver` |
| verifier error | the full verifier log is printed; see the last lines |



