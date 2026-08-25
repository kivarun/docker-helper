package main

import (
	"encoding/json"
	"os"
	"testing"
)

// readConfigJSON reads and parses the config file at path into a raw JSON map.
func readConfigJSON(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("cannot parse config: %v", err)
	}
	return raw
}
