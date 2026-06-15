// Command lattice-relay runs a Lattice relay node.
//
// The relay accepts QUIC connections from pairs of federation nodes, matches
// them by rendezvous token, and splices their streams bidirectionally. It sees
// only encrypted ciphertext — QUIC provides end-to-end encryption, so the relay
// cannot read messages, forge frames, or impersonate nodes. A compromised relay
// causes connectivity loss (DoS) but not confidentiality or integrity failure.
package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"lattice/internal/relay"
	quictransport "lattice/internal/transport/quic"
)

func main() {
	addr := flag.String("addr", ":4225", "QUIC relay listen address")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	listener, err := quictransport.Listen(*addr)
	if err != nil {
		log.Error("relay: listen failed", "addr", *addr, "err", err)
		os.Exit(1)
	}
	log.Info("lattice-relay listening", "addr", *addr)

	r := relay.New(listener, log)
	r.Start()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Info("signal received, shutting down relay")
	r.Stop()
	log.Info("goodbye")
}
