package quictransport

import (
	"crypto/tls"

	"lattice/internal/wire"
)

// ALPN is the TLS Application-Layer Protocol Negotiation identifier for
// node-to-node federation connections. Client connections use a different
// label ("lattice-hello-v1"), so ALPN isolates the two listener types.
const ALPN = "lattice-fed-v1"

// newServerTLSConfig builds a TLS 1.3 config for the QUIC federation listener.
// The certificate is ephemeral — regenerated each startup. The trust anchor is
// the Ed25519 signature in FedHello (Session 2), not the TLS certificate.
func newServerTLSConfig() (*tls.Config, error) {
	cert, err := wire.GenerateSelfSignedCert()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{ALPN},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// newClientTLSConfig builds a TLS 1.3 config for the QUIC federation dialer.
// Certificate verification is intentionally skipped; FedHello provides the
// trust anchor via Ed25519 signature over the TLS exporter material.
func newClientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // trust anchor is FedHello Ed25519 sig
		NextProtos:         []string{ALPN},
		MinVersion:         tls.VersionTLS13,
	}
}
