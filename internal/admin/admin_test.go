package admin_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"

	"lattice/internal/admin"
	"lattice/internal/schema"
	pb "lattice/proto"
)

// startServer binds a random loopback port and returns the base URL + stop fn.
func startServer(t *testing.T, r *schema.Registry) (baseURL string, stop func()) {
	t.Helper()
	a := admin.New(r)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go a.Serve(ln) //nolint:errcheck
	return "http://" + ln.Addr().String(), func() { ln.Close() }
}

func fdBytes(t *testing.T) []byte {
	t.Helper()
	fdp := protodesc.ToFileDescriptorProto((&pb.TemperatureReading{}).ProtoReflect().Descriptor().ParentFile())
	b, err := proto.Marshal(fdp)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestListenAndServeRejectsNonLoopback(t *testing.T) {
	a := admin.New(schema.DefaultRegistry())
	err := a.ListenAndServe("0.0.0.0:0")
	if err == nil {
		t.Fatal("expected error for non-loopback bind, got nil")
	}
}

func TestGetSchemaReturnsBuiltins(t *testing.T) {
	baseURL, stop := startServer(t, schema.DefaultRegistry())
	defer stop()

	resp, err := http.Get(baseURL + "/schema")
	if err != nil {
		t.Fatalf("GET /schema: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var list []schema.SubjectInfo
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(list) < 2 {
		t.Fatalf("expected at least 2 built-in schemas, got %d", len(list))
	}
}

func TestPostSchemaRegistersSubject(t *testing.T) {
	r := schema.DefaultRegistry()
	baseURL, stop := startServer(t, r)
	defer stop()

	body := map[string]string{
		"subject":      "home.sensor.humidity",
		"message_name": "TemperatureReading",
		"descriptor":   base64.StdEncoding.EncodeToString(fdBytes(t)),
	}
	b, _ := json.Marshal(body)
	resp, err := http.Post(baseURL+"/schema", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST /schema: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
	if r.Version("home.sensor.humidity") == 0 {
		t.Fatal("subject should be registered after successful POST")
	}
}

func TestPostSchemaInvalidBase64(t *testing.T) {
	baseURL, stop := startServer(t, schema.DefaultRegistry())
	defer stop()

	body := map[string]string{
		"subject":      "home.x",
		"message_name": "Foo",
		"descriptor":   "not-valid-base64!!!",
	}
	b, _ := json.Marshal(body)
	resp, err := http.Post(baseURL+"/schema", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST /schema: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid base64, got %d", resp.StatusCode)
	}
}

func TestPostSchemaInvalidJSON(t *testing.T) {
	baseURL, stop := startServer(t, schema.DefaultRegistry())
	defer stop()

	resp, err := http.Post(baseURL+"/schema", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("POST /schema: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

func TestPostSchemaBodyTooLarge(t *testing.T) {
	baseURL, stop := startServer(t, schema.DefaultRegistry())
	defer stop()

	// Build a JSON body whose string value exceeds 512 KiB so the JSON decoder
	// reads past the MaxBytesReader limit (a bare non-JSON body would fail
	// after the first byte, before the cap is reached).
	giant := `{"descriptor":"` + strings.Repeat("x", 513<<10) + `"}`
	resp, err := http.Post(baseURL+"/schema", "application/json", strings.NewReader(giant))
	if err != nil {
		t.Fatalf("POST /schema: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized body, got %d", resp.StatusCode)
	}
}
