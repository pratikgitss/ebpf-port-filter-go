// Command procfilter lets one named process connect to a single TCP port only.
// Every other TCP connect() by that process is rejected; other processes are
// not affected. It uses cgroup/connect4 and cgroup/connect6 eBPF programs,
// which run inside the process's own connect() call and so know its name.
//
//	sudo ./procfilter [--comm myprocess] [--port 4040] [--cgroup /sys/fs/cgroup]
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel procfilter ../../bpf/procfilter.bpf.c

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"ebpf-demo/internal/config"
)

const reportEvery = 5 * time.Second

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	if err := run(os.Args[1:]); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Fprintf(os.Stderr, "verifier log:\n%+v\n", ve)
		}
		slog.Error("procfilter failed", "err", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("procfilter", flag.ContinueOnError)
	comm := fs.String("comm", "myprocess", "name of the process to restrict")
	portFlag := fs.Int("port", 4040, "the only TCP port that process may connect to")
	cgroupPath := fs.String("cgroup", "/sys/fs/cgroup", "cgroup v2 directory to attach to (the root covers every process)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := config.ValidateComm(*comm); err != nil {
		return err
	}
	port, err := config.ValidatePort(*portFlag)
	if err != nil {
		return err
	}
	// The kernel keeps only the first 15 bytes of a process name, so match on that.
	name := *comm
	if len(name) > config.MaxCommNameLen {
		name = name[:config.MaxCommNameLen]
		slog.Warn("process name is longer than 15 bytes; truncating like the kernel does",
			"given", *comm, "used", name)
	}
	if fi, err := os.Stat(*cgroupPath); err != nil || !fi.IsDir() {
		return fmt.Errorf("cgroup path %q is not a directory (is cgroup v2 mounted?): %v", *cgroupPath, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock limit: %w", err)
	}

	var objs procfilterObjects
	if err := loadProcfilterObjects(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	// Configure the maps before attaching, so the program never runs unconfigured.
	if err := objs.TargetComm.Put(uint32(0), config.CommBytes(*comm)); err != nil {
		return fmt.Errorf("write process name to map: %w", err)
	}
	if err := objs.AllowedPort.Put(uint32(0), uint32(port)); err != nil {
		return fmt.Errorf("write allowed port to map: %w", err)
	}

	// IPv4 and IPv6 destinations go through different hooks; attach both so
	// the process cannot bypass the rule by connecting over IPv6.
	l4, err := attachConnect(*cgroupPath, ebpf.AttachCGroupInet4Connect, objs.CheckConnect4)
	if err != nil {
		return fmt.Errorf("attach connect4: %w", err)
	}
	defer l4.Close()

	l6, err := attachConnect(*cgroupPath, ebpf.AttachCGroupInet6Connect, objs.CheckConnect6)
	if err != nil {
		return fmt.Errorf("attach connect6: %w", err)
	}
	defer l6.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("restricting process", "comm", name, "allowed_port", port, "cgroup", *cgroupPath)
	slog.Info("press Ctrl+C to detach and exit")

	reportRejects(ctx, objs.Rejected)

	total, err := sumPerCPU(objs.Rejected)
	if err != nil {
		slog.Warn("read reject counter", "err", err)
	}
	slog.Info("detaching", "rejected_total", total)
	return nil
}

func attachConnect(cgroupPath string, typ ebpf.AttachType, prog *ebpf.Program) (link.Link, error) {
	return link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  typ,
		Program: prog,
	})
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

// reportRejects logs the reject counter whenever it changes, until ctx is done.
func reportRejects(ctx context.Context, counter *ebpf.Map) {
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
				slog.Warn("read reject counter", "err", err)
				continue
			}
			if total != last {
				slog.Info("rejected connect() calls", "total", total)
				last = total
			}
		}
	}
}
