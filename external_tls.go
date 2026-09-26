package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
)

// validateExternalTLSConfig is intentionally narrow: this local-only fork
// accepts an all-or-nothing TLS configuration, with an IP literal bind address.
// The existing plaintext listener remains restricted to loopback.
func validateExternalTLSConfig(raw map[string]json.RawMessage) error {
	fields := []string{"tls_address", "tls_cert_file", "tls_key_file"}
	values := make(map[string]string, len(fields))
	configured := 0
	for _, name := range fields {
		value, present := raw[name]
		if !present {
			continue
		}
		configured++
		var parsed string
		if err := json.Unmarshal(value, &parsed); err != nil || parsed == "" {
			return fmt.Errorf("%s must be a non-empty JSON string", name)
		}
		values[name] = parsed
	}
	if configured == 0 {
		return nil
	}
	if configured != len(fields) {
		return fmt.Errorf("external TLS requires tls_address, tls_cert_file and tls_key_file together")
	}

	host, port, err := net.SplitHostPort(values["tls_address"])
	if err != nil || net.ParseIP(host) == nil {
		return fmt.Errorf("tls_address must be an IP literal and port, for example 192.168.1.10:52376")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("tls_address port must be 1..65535")
	}
	for _, field := range fields[1:] {
		if !filepath.IsAbs(values[field]) {
			return fmt.Errorf("%s must be an absolute path", field)
		}
	}
	return nil
}

// startExternalTLSListener never generates certificates or falls back to HTTP.
// The operator supplies the complete PEM certificate chain and matching key.
// Both files are read on startup; restarting the daemon loads replacements.
func startExternalTLSListener(cfg *Config) (net.Listener, error) {
	if cfg.TLSAddress == "" {
		return nil, nil
	}
	pair, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("cannot load external TLS certificate/key: %w", err)
	}
	listener, err := net.Listen("tcp", cfg.TLSAddress)
	if err != nil {
		return nil, fmt.Errorf("cannot bind external TLS listener %s: %w", cfg.TLSAddress, err)
	}
	return tls.NewListener(listener, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
	}), nil
}
