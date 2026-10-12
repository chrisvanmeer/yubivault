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

// readLines returns the non-empty raw lines of an audit file.
func readLines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var out [][]byte
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, []byte(line))
		}
	}
	return out
}

func TestVerifyChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Log(Event{Event: EventLogin, Outcome: OutcomeSuccess, Identity: "chris"})
	l.Log(Event{Event: EventIssue, Outcome: OutcomeSuccess, Identity: "chris", YubiKeyFingerprint: "sha256:abc"})
	l.Log(Event{Event: EventLogout, Outcome: OutcomeSuccess, Identity: "chris"})
	_ = l.Close()

	line, err := Verify(path)
	if err != nil || line != 0 {
		t.Fatalf("Verify = (%d, %v), want (0, nil)", line, err)
	}

	// The first record must chain from the genesis hash.
	records := readLines(t, path)
	var first struct {
		PrevHash string `json:"prev_hash"`
	}
	if err := json.Unmarshal(records[0], &first); err != nil {
		t.Fatal(err)
	}
	if first.PrevHash != genesisHash() {
		t.Errorf("first prev_hash = %s, want genesis %s", first.PrevHash, genesisHash())
	}
}

func TestVerifyContinuesAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Log(Event{Event: EventLogin, Outcome: OutcomeSuccess})
	_ = l.Close()

	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l2.Log(Event{Event: EventLogout, Outcome: OutcomeSuccess})
	_ = l2.Close()

	if line, err := Verify(path); err != nil || line != 0 {
		t.Fatalf("Verify after reopen = (%d, %v), want (0, nil)", line, err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Log(Event{Event: EventLogin, Outcome: OutcomeSuccess, Identity: "chris"})
	l.Log(Event{Event: EventIssue, Outcome: OutcomeSuccess, Identity: "chris"})
	l.Log(Event{Event: EventLogout, Outcome: OutcomeSuccess, Identity: "chris"})
	_ = l.Close()

	records := readLines(t, path)
	// Rewrite the first record to forge the identity. It still chains from
	// genesis, but its hash changes, so the second record no longer links.
	var forged Event
	if err := json.Unmarshal(records[0], &forged); err != nil {
		t.Fatal(err)
	}
	forged.Identity = "attacker"
	newFirst, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	records[0] = newFirst

	var buf strings.Builder
	for _, r := range records {
		buf.Write(r)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(buf.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	line, err := Verify(path)
	if err == nil {
		t.Fatal("Verify should detect the forged record")
	}
	if line != 2 {
		t.Errorf("Verify reported line %d, want 2 (the link to the forged record)", line)
	}
}

func TestVerifyMissingPrevHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	// A record without prev_hash is not part of the chain.
	content := `{"time":"2024-01-01T00:00:00Z","event":"login","outcome":"success"}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	line, err := Verify(path)
	if err == nil || line != 1 {
		t.Fatalf("Verify = (%d, %v), want (1, error)", line, err)
	}
}

func TestVerifyDetectsInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	line, err := Verify(path)
	if err == nil || line != 1 {
		t.Fatalf("Verify = (%d, %v), want (1, error)", line, err)
	}
}
