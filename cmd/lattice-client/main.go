package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"lattice/internal/handshake"
	"lattice/internal/identity"
	"lattice/internal/wire"
	pb "lattice/proto"
)

func main() {
	addr := flag.String("addr", "localhost:4222", "lattice-node address")
	keyFile := flag.String("key", "client.key", "Ed25519 private key file (created if missing)")
	flag.Parse()

	_, clientPriv, err := identity.LoadOrGenerate(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load/generate key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("identity loaded from %s\n", *keyFile)

	conn, err := tls.Dial("tcp", *addr, &tls.Config{
		InsecureSkipVerify: true, // self-signed cert; replaced by CA pinning in later sessions
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Printf("connected to %s\n", *addr)

	cs, err := handshake.DoClient(conn, clientPriv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "handshake: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("authenticated  session_id=%s  heartbeat_interval=%s\n",
		cs.SessionID, cs.HeartbeatInterval)

	// Mutex protecting all writes so the heartbeat goroutine and main goroutine
	// don't interleave their frame bytes.
	var writeMu sync.Mutex
	writeFrame := func(ft pb.FrameType, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return wire.Write(conn, ft, payload)
	}

	// Heartbeat goroutine.
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(cs.HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := writeFrame(pb.FrameType_FRAME_TYPE_HEARTBEAT, nil); err != nil {
					return
				}
			case <-stop:
				return
			}
		}
	}()

	// Read loop — prints every server-pushed frame.
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			frame, err := wire.Read(conn)
			if err != nil {
				return
			}
			switch frame.Type {
			case pb.FrameType_FRAME_TYPE_HEARTBEAT_ACK:
				fmt.Println("← HEARTBEAT_ACK")
			default:
				fmt.Printf("← %s  %d bytes\n", frame.Type, len(frame.Payload))
			}
		}
	}()

	// Wait for Ctrl+C or connection drop.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
		fmt.Println("\ndisconnecting...")
	case <-readDone:
		fmt.Println("server closed the connection")
	}
	close(stop)
}
