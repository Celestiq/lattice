package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"

	"lattice/internal/identity"
	"lattice/internal/node"
	"lattice/internal/wire"
)

func main() {
	addr := flag.String("addr", ":4222", "listen address")
	keyFile := flag.String("key", "node.key", "Ed25519 private key file (created if missing)")
	heartbeatInterval := flag.Uint("heartbeat", 30, "heartbeat interval sent to clients (seconds)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	_, serverPriv, err := identity.LoadOrGenerate(*keyFile)
	if err != nil {
		log.Error("load/generate server key", "err", err)
		os.Exit(1)
	}
	log.Info("server identity loaded", "key_file", *keyFile)

	cert, err := wire.GenerateSelfSignedCert()
	if err != nil {
		log.Error("generate TLS cert", "err", err)
		os.Exit(1)
	}

	ln, err := tls.Listen("tcp", *addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	defer ln.Close()

	srv := node.New(log, serverPriv, uint32(*heartbeatInterval))
	log.Info("lattice-node listening", "addr", *addr, "tls", true)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Error("accept", "err", err)
			continue
		}
		go srv.HandleConn(conn)
	}
}
