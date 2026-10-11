package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogAppendsJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = l.Close() }()

	l.Log(Event{Event: EventLogin, Outcome: OutcomeSuccess, Identity: "chris", CN: "chris"})
	l.Log(Event{Event: EventIssueDenied, Outcome: OutcomeDenied, Reason: "bad key", Identity: "chris"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), data)
	}
	var first Event
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v", err)
	}
	if first.Event != EventLogin || first.Identity != "chris" || first.CN != "chris" {
		t.Errorf("unexpected first event: %+v", first)
	}
	if first.Time == "" {
		t.Error("timestamp missing")
	}
}

func TestLogAppendsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Log(Event{Event: EventLogout, Outcome: OutcomeSuccess})
	_ = l.Close()

	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l2.Close() }()
	l2.Log(Event{Event: EventLogout, Outcome: OutcomeSuccess})

	data, _ := os.ReadFile(path)
	if c := len(strings.Split(strings.TrimSpace(string(data)), "\n")); c != 2 {
		t.Errorf("expected 2 records after re-open, got %d", c)
	}
}

func TestNilLoggerNoOp(t *testing.T) {
	var l *Logger
	l.Log(Event{Event: EventLogin}) // must not panic
	if err := l.Close(); err != nil {
		t.Errorf("nil Close = %v", err)
	}
}

func TestOpenMissingDir(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "no", "dir", "audit.log")); err == nil {
		t.Error("expected error opening audit log in a missing directory")
	}
}
