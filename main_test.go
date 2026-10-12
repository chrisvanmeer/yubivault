package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestFileUnchanged verifies the config watchdog's change detection: identical
// modification time and size is treated as unchanged, so an unchanged file is
// never re-read or re-parsed.
func TestFileUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("server: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if fileUnchanged(nil, first) {
		t.Error("a missing previous snapshot must report a change")
	}
	if fileUnchanged(first, nil) {
		t.Error("a missing current snapshot must report a change")
	}
	if !fileUnchanged(first, first) {
		t.Error("the same snapshot must report unchanged")
	}

	// A size change with the same modification time must still be noticed.
	resized := fakeInfo{name: first.Name(), size: first.Size() + 1, mod: first.ModTime()}
	if fileUnchanged(first, resized) {
		t.Error("a different size must report a change")
	}

	// A modification-time change with the same size must be noticed too.
	retimed := fakeInfo{name: first.Name(), size: first.Size(), mod: first.ModTime().Add(time.Second)}
	if fileUnchanged(first, retimed) {
		t.Error("a different modification time must report a change")
	}
}

// fakeInfo is a minimal os.FileInfo for exercising the change comparison.
type fakeInfo struct {
	name string
	size int64
	mod  time.Time
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return f.size }
func (f fakeInfo) Mode() os.FileMode  { return 0o600 }
func (f fakeInfo) ModTime() time.Time { return f.mod }
func (f fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any           { return nil }
