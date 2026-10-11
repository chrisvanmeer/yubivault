// Package audit writes an append-only, machine readable audit trail of the
// security relevant events YubiVault handles: logins, issuance, denials and
// revocations. It deliberately never contains raw ID tokens or session
// secrets.
package audit

import (
	"encoding/json"
	"os"
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

	Identity        string `json:"identity,omitempty"`
	CN              string `json:"cn,omitempty"`
	Serial          string `json:"serial,omitempty"`
	Slot            string `json:"slot,omitempty"`
	KeyType         string `json:"key_type,omitempty"`
	YubiKeySerial   string `json:"yubikey_serial,omitempty"`
	YubiKeyFirmware string `json:"yubikey_firmware,omitempty"`
	RemoteIP        string `json:"remote_ip,omitempty"`
}

// Logger appends events to a file as one JSON object per line. It is safe for
// concurrent use. A nil *Logger is valid and makes Log a no-op.
type Logger struct {
	mu   sync.Mutex
	file *os.File
}

// Open opens (or creates) the audit log at path for appending. The file is
// created with 0640 permissions, matching the service log convention.
func Open(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	return &Logger{file: f}, nil
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
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.file.Write(append(line, '\n'))
}

// Close closes the underlying file.
func (l *Logger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}
