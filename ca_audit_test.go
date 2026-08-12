package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCAAuditBooleanOnly(t *testing.T) {
	rec := auditRecord{
		Event:             "run.start",
		SessionID:         "test-session",
		OperationID:       "test-op",
		Image:             "alpine:3.24",
		TrustedCAInjected: true,
	}

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	str := string(data)

	if !strings.Contains(str, `"trusted_ca_injected":true`) {
		t.Error("expected trusted_ca_injected:true in audit")
	}

	if strings.Contains(str, "/etc/") || strings.Contains(str, "docker-helper") {
		t.Error("audit should not contain host paths")
	}
}

func TestAuditRecordTrustedCAInjected(t *testing.T) {
	rec := auditRecord{
		Event:             "run.start",
		SessionID:         "s1",
		OperationID:       "o1",
		Image:             "alpine",
		TrustedCAInjected: true,
	}
	data, _ := json.Marshal(rec)
	if !strings.Contains(string(data), `"trusted_ca_injected":true`) {
		t.Error("expected trusted_ca_injected:true")
	}

	rec2 := auditRecord{
		Event:             "run.start",
		SessionID:         "s1",
		OperationID:       "o1",
		Image:             "alpine",
		TrustedCAInjected: false,
	}
	data2, _ := json.Marshal(rec2)
	if strings.Contains(string(data2), "trusted_ca_injected") {
		t.Error("trusted_ca_injected should be omitted when false")
	}
}
