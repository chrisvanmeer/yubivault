// Package audit writes an append-only, machine readable audit trail of the
// security relevant events YubiVault handles: logins, issuance, denials and
// revocations. It deliberately never contains raw ID tokens or session
// secrets.
//
// Records are chained: every line carries the SHA-256 of the previous raw
// line as prev_hash, so tampering with any earlier record breaks the chain at
// the next record. The chain starts from a fixed genesis hash and continues
// across process restarts. audit.Verify detects the first broken link.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Event names.
const (
	EventLogin       = "login"
	EventLoginDenied = "login_denied"
	EventIssue       = "issue"
	EventIssueDenied = "issue_denied"
	EventRevoke      = "revoke"
	EventLogout      = "logout"
)

// Outcomes.
const (
	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"
	OutcomeError   = "error"
)

// genesisSeed anchors the start of the hash chain. The genesis hash is the
// SHA-256 of this fixed string; it is never itself written to the log.
const genesisSeed = "yubivault-audit-v1"

// Event is one audit log record. Optional fields use omitempty so a denied
// request does not leak half filled slots.
type Event struct {
	// Time is the event timestamp in RFC3339 UTC. It is set automatically on
	// Log when empty.
	Time string `json:"time"`
	// Event is one of the Event* constants.
	Event string `json:"event"`
	// Outcome is one of the Outcome* constants.
	Outcome string `json:"outcome,omitempty"`
	// Reason explains a denial or failure in free text.
	Reason string `json:"reason,omitempty"`
	// PrevHash chains this record to the SHA-256 of the previous raw line. It
	// is set automatically on Log.
	PrevHash string `json:"prev_hash,omitempty"`

	Identity           string `json:"identity,omitempty"`
	CN                 string `json:"cn,omitempty"`
	Serial             string `json:"serial,omitempty"`
	Slot               string `json:"slot,omitempty"`
	KeyType            string `json:"key_type,omitempty"`
	YubiKeySerial      string `json:"yubikey_serial,omitempty"`
	YubiKeyFirmware    string `json:"yubikey_firmware,omitempty"`
	YubiKeyFingerprint string `json:"yubikey_fingerprint,omitempty"`
	RemoteIP           string `json:"remote_ip,omitempty"`
}

// Logger appends events to a file as one JSON object per line. It is safe for
// concurrent use. A nil *Logger is valid and makes Log a no-op.
type Logger struct {
	mu       sync.Mutex
	file     *os.File
	prevHash string
}

// Open opens (or creates) the audit log at path for appending. The file is
// created with 0640 permissions, matching the service log convention. When
// the file already holds records the chain continues from the last line;
// when the file is empty or absent it starts from the genesis hash.
func Open(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	prevHash := genesisHash()
	if data, err := os.ReadFile(path); err == nil {
		if last := lastRecord(data); last != nil {
			prevHash = hashLine(last)
		}
	}
	return &Logger{file: f, prevHash: prevHash}, nil
}

// Log writes one event. When the logger is nil or the underlying file is
// closed the call is a no-op.
func (l *Logger) Log(e Event) {
	if l == nil || l.file == nil {
		return
	}
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	e.PrevHash = l.prevHash
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	if _, err := l.file.Write(append(line, '\n')); err != nil {
		return
	}
	l.prevHash = hashLine(line)
}

// Close closes the underlying file.
func (l *Logger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

// Verify walks the chained audit log at path from the genesis hash and
// reports the line number of the first record whose prev_hash does not match
// the hash of the preceding line. It returns (0, nil) when every record in
// the file (including a final partial line) verifies. A Parse error or a
// record missing prev_hash is reported as a broken link too.
func Verify(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	prev := genesisHash()
	lineNo := 0
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		lineNo++
		var rec struct {
			PrevHash string `json:"prev_hash"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			return lineNo, fmt.Errorf("line %d is not a valid JSON record: %w", lineNo, err)
		}
		if rec.PrevHash == "" {
			return lineNo, fmt.Errorf("line %d is missing prev_hash (not part of the chain)", lineNo)
		}
		if !strings.EqualFold(rec.PrevHash, prev) {
			return lineNo, fmt.Errorf("line %d breaks the chain: prev_hash %s does not match the previous line (%s)",
				lineNo, rec.PrevHash, prev)
		}
		prev = hashLine(line)
	}
	return 0, nil
}

// genesisHash returns the fixed hash that starts every audit chain.
func genesisHash() string {
	sum := sha256.Sum256([]byte(genesisSeed))
	return hex.EncodeToString(sum[:])
}

// hashLine returns the hex SHA-256 of one raw audit line (without the
// trailing newline, but including any other whitespace exactly as written).
func hashLine(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// lastRecord returns the final non-empty line of audit data, or nil when the
// file has none.
func lastRecord(data []byte) []byte {
	lines := bytes.Split(data, []byte{'\n'})
	for i := len(lines) - 1; i >= 0; i-- {
		if len(bytes.TrimSpace(lines[i])) > 0 {
			return lines[i]
		}
	}
	return nil
}
