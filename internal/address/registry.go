// Package address implements the Lattice address registry.
//
// The registry allows federation nodes to register their current IPv6
// federation address so that peers can look it up without knowing it in
// advance. It also delivers push notifications when a node's address changes.
//
// Protocol (all over QUIC streams):
//
//	Registration:  node → registry   REGISTRY_REGISTER{pubkey, addr, known_peers}
//	               registry → node   REGISTRY_REGISTER_ACK
//
//	Lookup:        node → registry   REGISTRY_LOOKUP{pubkey}
//	               registry → node   REGISTRY_LOOKUP_RESULT{addr}  (empty if unknown)
//
//	Notification:  registry → peer   REGISTRY_NOTIFY{pubkey, addr}  (pushed on change)
//
// Notifications are pushed over a fresh short-lived QUIC connection to the
// peer's registered federation address. The peer's federation manager handles
// these frames at the top of its accept loop.
package address

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"lattice/internal/transport"
	"lattice/internal/wire"
	pb "lattice/proto"
)

// ─── Server ──────────────────────────────────────────────────────────────────

// Server is the address registry daemon. It stores node addresses and
// pushes notifications when addresses change.
type Server struct {
	listener transport.Listener
	dialer   transport.Dialer
	nodes    sync.Map // hex(pubkey) → *nodeEntry
	log      *slog.Logger
	wg       sync.WaitGroup
	done     chan struct{}
}

type nodeEntry struct {
	mu         sync.Mutex
	addr       string
	knownPeers [][]byte // pubkeys of peers to notify on address change
}

// NewServer creates a Server. dialer is used to push notifications to peers.
func NewServer(listener transport.Listener, dialer transport.Dialer, log *slog.Logger) *Server {
	return &Server{
		listener: listener,
		dialer:   dialer,
		log:      log,
		done:     make(chan struct{}),
	}
}

// Start begins accepting connections. It returns immediately; call Stop() to shut down.
func (s *Server) Start() {
	s.wg.Add(1)
	go s.runAcceptLoop()
}

// Stop shuts down the server and waits for all goroutines to exit.
func (s *Server) Stop() {
	close(s.done)
	s.listener.Close() //nolint:errcheck
	s.wg.Wait()
}

func (s *Server) runAcceptLoop() {
	defer s.wg.Done()
	ctx := context.Background()
	for {
		select {
		case <-s.done:
			return
		default:
		}
		stream, err := s.listener.AcceptPeer(ctx)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				s.log.Error("registry: accept error", "err", err)
				return
			}
		}
		s.wg.Add(1)
		go func(st transport.Stream) {
			defer s.wg.Done()
			s.handleConn(st)
		}(stream)
	}
}

func (s *Server) handleConn(stream transport.Stream) {
	// Do NOT defer stream.Close() here. On this QUIC transport Close() calls
	// conn.CloseWithError which is a hard close that drops buffered data. Instead,
	// after sending the response we drain until the client closes its side;
	// the client drives connection teardown.
	stream.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	f, err := wire.Read(stream)
	stream.SetDeadline(time.Time{}) //nolint:errcheck
	if err != nil {
		return
	}
	switch f.Type {
	case pb.FrameType_FRAME_TYPE_REGISTRY_REGISTER:
		s.handleRegister(stream, f)
	case pb.FrameType_FRAME_TYPE_REGISTRY_LOOKUP:
		s.handleLookup(stream, f)
	default:
		s.log.Warn("registry: unexpected frame", "type", f.Type)
		return
	}
	// Drain until client closes or short deadline — ensures buffered response
	// frames are delivered before the connection drops.
	stream.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	io.Copy(io.Discard, stream)                         //nolint:errcheck
}

func (s *Server) handleRegister(stream transport.Stream, f *wire.Frame) {
	var reg pb.RegistryRegister
	if err := proto.Unmarshal(f.Payload, &reg); err != nil {
		return
	}
	if len(reg.Pubkey) != 32 || reg.Addr == "" {
		return
	}
	pubHex := hex.EncodeToString(reg.Pubkey)

	var prevAddr string
	peers := make([][]byte, len(reg.KnownPeers))
	for i, p := range reg.KnownPeers {
		cp := make([]byte, len(p))
		copy(cp, p)
		peers[i] = cp
	}

	// Upsert entry and capture the previous address for change detection.
	newEntry := &nodeEntry{addr: reg.Addr, knownPeers: peers}
	if actual, loaded := s.nodes.LoadOrStore(pubHex, newEntry); loaded {
		existing := actual.(*nodeEntry)
		existing.mu.Lock()
		prevAddr = existing.addr
		existing.addr = reg.Addr
		existing.knownPeers = peers
		existing.mu.Unlock()
	}

	ackB, _ := proto.Marshal(&pb.RegistryRegisterAck{})
	wire.Write(stream, pb.FrameType_FRAME_TYPE_REGISTRY_REGISTER_ACK, ackB) //nolint:errcheck

	// Push notifications to known peers if the address changed.
	if prevAddr != "" && prevAddr != reg.Addr {
		notifyB, _ := proto.Marshal(&pb.RegistryNotify{Pubkey: reg.Pubkey, Addr: reg.Addr})
		for _, peerPub := range peers {
			ph := hex.EncodeToString(peerPub)
			peerAddrStr := s.lookupAddr(ph)
			if peerAddrStr == "" {
				continue
			}
			peerPubCopy := peerPub
			notifyBCopy := notifyB
			peerAddrCopy := peerAddrStr
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.pushNotify(peerAddrCopy, peerPubCopy, notifyBCopy)
			}()
		}
	}
}

func (s *Server) handleLookup(stream transport.Stream, f *wire.Frame) {
	var lookup pb.RegistryLookup
	if err := proto.Unmarshal(f.Payload, &lookup); err != nil {
		return
	}
	addr := s.lookupAddr(hex.EncodeToString(lookup.Pubkey))
	resultB, _ := proto.Marshal(&pb.RegistryLookupResult{Addr: addr})
	wire.Write(stream, pb.FrameType_FRAME_TYPE_REGISTRY_LOOKUP_RESULT, resultB) //nolint:errcheck
}

func (s *Server) lookupAddr(pubHex string) string {
	v, ok := s.nodes.Load(pubHex)
	if !ok {
		return ""
	}
	e := v.(*nodeEntry)
	e.mu.Lock()
	addr := e.addr
	e.mu.Unlock()
	return addr
}

func (s *Server) pushNotify(peerAddr string, peerPub []byte, notifyPayload []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := s.dialer.DialPeer(ctx, peerAddr)
	if err != nil {
		s.log.Warn("registry: notify dial failed", "peer", hex.EncodeToString(peerPub)[:8], "err", err)
		return
	}
	// No defer stream.Close() here — same QUIC close-before-read race as
	// handleConn. Drain until the peer closes the connection.
	stream.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	wire.Write(stream, pb.FrameType_FRAME_TYPE_REGISTRY_NOTIFY, notifyPayload) //nolint:errcheck
	stream.SetDeadline(time.Now().Add(2 * time.Second))                        //nolint:errcheck
	io.Copy(io.Discard, stream)                                                 //nolint:errcheck
}

// ─── Client ──────────────────────────────────────────────────────────────────

// Client communicates with an address registry on behalf of a federation node.
type Client struct {
	registryAddr string
	dialer       transport.Dialer
}

// NewClient creates a registry client that talks to registryAddr.
func NewClient(registryAddr string, dialer transport.Dialer) *Client {
	return &Client{registryAddr: registryAddr, dialer: dialer}
}

// Register sends the node's current federation address and known peers to the
// registry. The registry will push REGISTRY_NOTIFY frames to known peers when
// this node's address changes in a future Register call.
func (c *Client) Register(ctx context.Context, localPub []byte, myAddr string, knownPeers [][]byte) error {
	stream, err := c.dialer.DialPeer(ctx, c.registryAddr)
	if err != nil {
		return err
	}
	defer stream.Close() //nolint:errcheck
	stream.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck

	reg := &pb.RegistryRegister{Pubkey: localPub, Addr: myAddr, KnownPeers: knownPeers}
	b, err := proto.Marshal(reg)
	if err != nil {
		return err
	}
	if err := wire.Write(stream, pb.FrameType_FRAME_TYPE_REGISTRY_REGISTER, b); err != nil {
		return err
	}
	f, err := wire.Read(stream)
	if err != nil {
		return err
	}
	if f.Type != pb.FrameType_FRAME_TYPE_REGISTRY_REGISTER_ACK {
		return fmt.Errorf("registry: expected REGISTER_ACK, got %v", f.Type)
	}
	return nil
}

// Lookup returns the current federation address of the node identified by
// peerPub. Returns ("", nil) if the peer has not registered.
func (c *Client) Lookup(ctx context.Context, peerPub []byte) (string, error) {
	stream, err := c.dialer.DialPeer(ctx, c.registryAddr)
	if err != nil {
		return "", err
	}
	defer stream.Close() //nolint:errcheck
	stream.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck

	b, err := proto.Marshal(&pb.RegistryLookup{Pubkey: peerPub})
	if err != nil {
		return "", err
	}
	if err := wire.Write(stream, pb.FrameType_FRAME_TYPE_REGISTRY_LOOKUP, b); err != nil {
		return "", err
	}
	f, err := wire.Read(stream)
	if err != nil {
		return "", err
	}
	if f.Type != pb.FrameType_FRAME_TYPE_REGISTRY_LOOKUP_RESULT {
		return "", fmt.Errorf("registry: expected LOOKUP_RESULT, got %v", f.Type)
	}
	var result pb.RegistryLookupResult
	if err := proto.Unmarshal(f.Payload, &result); err != nil {
		return "", err
	}
	return result.Addr, nil
}
