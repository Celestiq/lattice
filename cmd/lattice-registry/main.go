// Command lattice-registry runs a Lattice address registry.
//
// The registry stores federation node addresses and pushes notifications when
// addresses change. It allows federation nodes to find each other without
// having a pre-configured static address, enabling dynamic address updates
// (e.g., after a DHCP change or container restart).
package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"lattice/internal/address"
	quictransport "lattice/internal/transport/quic"
)

func main() {
	addr := flag.String("addr", ":4226", "QUIC registry listen address")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	listener, err := quictransport.Listen(*addr)
	if err != nil {
		log.Error("registry: listen failed", "addr", *addr, "err", err)
		os.Exit(1)
	}
	log.Info("lattice-registry listening", "addr", *addr)

	dialer := quictransport.NewDialer()
	srv := address.NewServer(listener, dialer, log)
	srv.Start()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Info("signal received, shutting down registry")
	srv.Stop()
	log.Info("goodbye")
}
