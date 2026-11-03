// Command demoserver listens on one or more TCP ports and answers every HTTP
// request with a short message. It is only used to demo portdrop and procfilter.
//
//	go run ./cmd/demoserver 4040 5050 8080
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("demoserver failed", "err", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	ports := args
	if len(ports) == 0 {
		ports = []string{"4040"}
	}
	for _, p := range ports {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid port %q", p)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	servers := make([]*http.Server, 0, len(ports))
	errc := make(chan error, len(ports))
	var wg sync.WaitGroup

	for _, port := range ports {
		port := port
		srv := &http.Server{
			Addr: ":" + port, // all interfaces, IPv4 and IPv6
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintf(w, "hello from port %s\n", port)
			}),
			ReadHeaderTimeout: 5 * time.Second,
		}
		// Listen eagerly so a port that is already in use is reported at startup.
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", srv.Addr, err)
		}
		servers = append(servers, srv)

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("serve port %s: %w", port, err)
			}
		}()
		slog.Info("listening", "port", port)
	}

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx)
	}
	wg.Wait()
	return nil
}
