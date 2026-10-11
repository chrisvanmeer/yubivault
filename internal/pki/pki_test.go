package pki

import (
	"encoding/json"
	"testing"
)

// TestToInt64 guards the revoked/expired detection: the Vault API decodes JSON
// numbers as json.Number (not float64), so toInt64 must understand them or
// revoked certificates are reported as active.
func TestToInt64(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want int64
		ok   bool
	}{
		{"int64", int64(5), 5, true},
		{"int", 5, 5, true},
		{"float64", float64(5), 5, true},
		{"json.Number", json.Number("1700000000"), 1700000000, true},
		{"string number", "1700000000", 1700000000, true},
		{"invalid json.Number", json.Number("abc"), 0, false},
		{"nil", nil, 0, false},
	}
	for _, tc := range cases {
		got, ok := toInt64(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s: toInt64(%v) = %d, %v; want %d, %v", tc.name, tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
