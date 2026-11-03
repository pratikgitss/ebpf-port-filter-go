// Command portdrop drops incoming TCP packets on a configurable port using an
// XDP eBPF program.
//
//	sudo ./portdrop [--iface lo] [--port 4040] [--generic]
//	sudo ./portdrop set-port 5050     # change the port of a running instance
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel portdrop ../../bpf/portdrop.bpf.c

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"ebpf-demo/internal/config"
)

const (
	// The config map is pinned here so `portdrop set-port` can find it.
	pinDir    = "/sys/fs/bpf/portdrop"
	configPin = pinDir + "/config"

	reportEvery = 5 * time.Second
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	if err := run(os.Args[1:]); err != nil {
		// A verifier rejection carries a long log that explains exactly what is wrong.
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Fprintf(os.Stderr, "verifier log:\n%+v\n", ve)
		}
		slog.Error("portdrop failed", "err", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "set-port" {
		return setPort(args[1:])
	}
	return serve(args)
}

// serve loads the XDP program, configures it and keeps it attached until
// Ctrl+C or SIGTERM.
func serve(args []string) error {
	fs := flag.NewFlagSet("portdrop", flag.ContinueOnError)
	ifaceName := fs.String("iface", "lo", "network interface to attach the XDP program to")
	portFlag := fs.Int("port", 4040, "TCP destination port to drop")
	generic := fs.Bool("generic", false, "force XDP generic (skb) mode instead of trying native mode first")
	if err := fs.Parse(args); err != nil {
		return err
	}

	port, err := config.ValidatePort(*portFlag)
	if err != nil {
		return err
	}
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		return fmt.Errorf("find interface %q: %w", *ifaceName, err)
	}

	// Needed on kernels older than 5.11; harmless on newer ones.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}

	// Loading runs the kernel verifier on the program.
	var objs portdropObjects
	if err := loadPortdropObjects(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	// Userspace -> kernel: the C program reads this value on every packet.
	if err := objs.Config.Put(uint32(0), uint32(port)); err != nil {
		return fmt.Errorf("write port to config map: %w", err)
	}

	l, err := attachXDP(objs.DropTcpPort, iface.Index, *generic)
	if err != nil {
		return fmt.Errorf("attach XDP to %s: %w", iface.Name, err)
	}
	defer l.Close()

	// Pinning is only needed for `set-port`; failing to pin is not fatal.
	if pinConfig(objs.Config) {
		defer unpinConfig(objs.Config)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("dropping TCP packets", "iface", iface.Name, "port", port)
	slog.Info("press Ctrl+C to detach and exit")

	reportDrops(ctx, objs.Dropped)

	total, err := sumPerCPU(objs.Dropped)
	if err != nil {
		slog.Warn("read drop counter", "err", err)
	}
	slog.Info("detaching", "dropped_total", total)
	return nil
}

// attachXDP attaches prog to the interface. Native (driver) mode is tried first;
// if the driver does not support it (e.g. lo), it falls back to generic mode.
func attachXDP(prog *ebpf.Program, ifindex int, forceGeneric bool) (link.Link, error) {
	flags := link.XDPAttachFlags(0)
	if forceGeneric {
		flags = link.XDPGenericMode
	}

	l, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: ifindex, Flags: flags})
	if err == nil || forceGeneric {
		return l, err
	}

	slog.Warn("default XDP attach failed, retrying in generic mode", "err", err)
	return link.AttachXDP(link.XDPOptions{Program: prog, Interface: ifindex, Flags: link.XDPGenericMode})
}

// sumPerCPU adds up a per-CPU counter: the kernel keeps one value per CPU.
func sumPerCPU(m *ebpf.Map) (uint64, error) {
	var perCPU []uint64
	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}

// reportDrops logs the drop counter whenever it changes, until ctx is done.
func reportDrops(ctx context.Context, counter *ebpf.Map) {
	ticker := time.NewTicker(reportEvery)
	defer ticker.Stop()

	var last uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			total, err := sumPerCPU(counter)
			if err != nil {
				slog.Warn("read drop counter", "err", err)
				continue
			}
			if total != last {
				slog.Info("dropped packets", "total", total)
				last = total
			}
		}
	}
}

// pinConfig exposes the config map under /sys/fs/bpf so another process can
// update it. It reports whether the pin succeeded.
func pinConfig(m *ebpf.Map) bool {
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		slog.Warn("cannot create pin directory; set-port will not work", "dir", pinDir, "err", err)
		return false
	}
	// Remove a stale pin left behind by a crashed run.
	if err := os.Remove(configPin); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("cannot remove stale pin", "path", configPin, "err", err)
	}
	if err := m.Pin(configPin); err != nil {
		slog.Warn("cannot pin config map; set-port will not work", "path", configPin, "err", err)
		return false
	}
	return true
}

func unpinConfig(m *ebpf.Map) {
	if err := m.Unpin(); err != nil {
		slog.Warn("unpin config map", "err", err)
	}
	_ = os.Remove(pinDir) // only succeeds when empty; ignore otherwise
}

// setPort updates the port of an already running portdrop without reloading it.
func setPort(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: portdrop set-port <port>")
	}
	n, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", args[0], err)
	}
	port, err := config.ValidatePort(n)
	if err != nil {
		return err
	}

	m, err := ebpf.LoadPinnedMap(configPin, nil)
	if err != nil {
		return fmt.Errorf("open pinned map %s (is portdrop running?): %w", configPin, err)
	}
	defer m.Close()

	if err := m.Put(uint32(0), uint32(port)); err != nil {
		return fmt.Errorf("update port: %w", err)
	}
	slog.Info("port updated", "port", port)
	return nil
}
