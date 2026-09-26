package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func rawExternalTLS(fields map[string]any) map[string]json.RawMessage {
	raw := make(map[string]json.RawMessage, len(fields))
	for name, value := range fields {
		data, _ := json.Marshal(value)
		raw[name] = data
	}
	return raw
}

func TestExternalTLSConfigAllOrNothing(t *testing.T) {
	valid := map[string]any{
		"tls_address":   "192.168.1.10:52376",
		"tls_cert_file": "/tmp/server.crt",
		"tls_key_file":  "/tmp/server.key",
	}
	if err := validateExternalTLSConfig(nil); err != nil {
		t.Fatalf("disabled TLS: %v", err)
	}
	if err := validateExternalTLSConfig(rawExternalTLS(valid)); err != nil {
		t.Fatalf("complete TLS config: %v", err)
	}
	for name := range valid {
		partial := make(map[string]any, len(valid))
		for key, value := range valid {
			if key != name {
				partial[key] = value
			}
		}
		if err := validateExternalTLSConfig(rawExternalTLS(partial)); err == nil {
			t.Errorf("missing %s should fail", name)
		}
	}

	cases := []struct {
		name   string
		field  string
		value  any
	}{
		{"plaintext-style URL", "tls_address", "http://0.0.0.0:52376"},
		{"hostname instead of IP", "tls_address", "localhost:52376"},
		{"port zero", "tls_address", "0.0.0.0:0"},
		{"oversized port", "tls_address", "0.0.0.0:65536"},
		{"relative cert", "tls_cert_file", "server.crt"},
		{"relative key", "tls_key_file", "server.key"},
		{"empty key", "tls_key_file", ""},
		{"null key", "tls_key_file", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			values := make(map[string]any, len(valid))
			for key, value := range valid {
				values[key] = value
			}
			values[tc.field] = tc.value
			if err := validateExternalTLSConfig(rawExternalTLS(values)); err == nil {
				t.Fatalf("expected rejection of %s=%v", tc.field, tc.value)
			}
		})
	}
}

func TestExternalTLSStrictConfigIngest(t *testing.T) {
	raw := rawExternalTLS(map[string]any{
		"allowed_roots": []string{testAllowedRootDir(t)},
		"session_ttl": "1h",
		"tls_address": "192.168.1.10:52376",
		"tls_cert_file": "/etc/docker-helper/tls/server.crt",
		"tls_key_file": "/etc/docker-helper/tls/server.key",
	})
	if err := validateRawConfig(raw); err != nil {
		t.Fatalf("TLS rejected by strict config ingest: %v", err)
	}
	decoded, err := decodeFileConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.TLSAddress != "192.168.1.10:52376" || decoded.TLSCertFile == "" || decoded.TLSKeyFile == "" {
		t.Fatalf("TLS settings lost in config projection: %+v", decoded)
	}
	delete(raw, "tls_key_file")
	if err := validateRawConfig(raw); err == nil {
		t.Fatal("partial external TLS configuration passed strict ingest")
	}
}

func makeTestTLSFiles(t *testing.T) (certPath, keyPath string, roots *x509.CertPool) {
	t.Helper()
	// Test-only keypair: production requires operator-supplied PEM files.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "docker-helper TLS test"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath = filepath.Join(t.TempDir(), "server.crt")
	keyPath = filepath.Join(filepath.Dir(certPath), "server.key")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("cannot add test certificate")
	}
	return certPath, keyPath, roots
}

func TestExternalTLSListenerLiveHTTPSAndCoordinatedShutdown(t *testing.T) {
	if listener, err := startExternalTLSListener(&Config{}); err != nil || listener != nil {
		t.Fatalf("disabled TLS must not start a listener: %v, %v", listener, err)
	}
	if listener, err := startExternalTLSListener(&Config{
		TLSAddress: "127.0.0.1:0", TLSCertFile: "/missing/cert.pem", TLSKeyFile: "/missing/key.pem",
	}); err == nil || listener != nil {
		t.Fatal("configured TLS must fail closed on missing certificate/key")
	}

	certPath, keyPath, roots := makeTestTLSFiles(t)
	tlsListener, err := startExternalTLSListener(&Config{
		TLSAddress: "127.0.0.1:0", TLSCertFile: certPath, TLSKeyFile: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tlsListener.Close()

	unixPath := filepath.Join(t.TempDir(), "test.sock")
	unixListener, err := net.Listen("unix", unixPath)
	if err != nil {
		t.Fatal(err)
	}
	defer unixListener.Close()

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("tls-ok"))
	})}
	signalCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, stop, drain, err := serveHTTPUntilShutdown(signalCtx, server, unixListener, nil,
			func() time.Duration { return 3 * time.Second }, nil, tlsListener)
		<-drain
		stop()
		done <- err
	}()

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: roots, MinVersion: tls.VersionTLS12,
		}},
	}
	url := "https://" + tlsListener.Addr().String() + "/test"
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("external HTTPS request: %v", err)
	}
	buf := make([]byte, 6)
	n, readErr := resp.Body.Read(buf)
	resp.Body.Close()
	if readErr != nil && n == 0 {
		t.Fatalf("read HTTPS response: %v", readErr)
	}
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(buf[:n]), "tls-ok") {
		t.Fatalf("unexpected HTTPS response: %d %q", resp.StatusCode, string(buf[:n]))
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("coordinated shutdown: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("TLS and Unix listeners did not shut down")
	}
}
