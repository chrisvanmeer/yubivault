package pki

import (
	"encoding/json"
	"testing"
	"time"
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

func TestSortCertificates(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	certs := []ActiveCert{
		{Serial: "oldest", NotAfter: base.AddDate(0, 0, 1)},
		{Serial: "newest", NotAfter: base.AddDate(0, 0, 3)},
		{Serial: "middle", NotAfter: base.AddDate(0, 0, 2)},
	}
	sortCertificates(certs)

	want := []string{"newest", "middle", "oldest"}
	for i, w := range want {
		if certs[i].Serial != w {
			t.Fatalf("position %d = %q, want %q (order: %v)", i, certs[i].Serial, w, serials(certs))
		}
	}

	tie := []ActiveCert{
		{Serial: "aaa", NotAfter: base},
		{Serial: "bbb", NotAfter: base},
	}
	sortCertificates(tie)
	if tie[0].Serial != "bbb" || tie[1].Serial != "aaa" {
		t.Errorf("equal expiries should break on serial descending, got %v", serials(tie))
	}
}

func serials(certs []ActiveCert) []string {
	out := make([]string, len(certs))
	for i, c := range certs {
		out[i] = c.Serial
	}
	return out
}
