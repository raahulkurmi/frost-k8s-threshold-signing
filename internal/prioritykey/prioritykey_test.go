package prioritykey

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRoundTripAndFailClosed(t *testing.T) {
	f, err := Generate("kid-1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(f)
	k, err := Parse(b, "kid-1")
	if err != nil || len(k) != Size {
		t.Fatalf("round trip: %v (len %d)", err, len(k))
	}
	g, _ := Generate("kid-1")
	if g.Key == f.Key {
		t.Fatal("two generated keys are equal")
	}
	for name, in := range map[string]string{
		"wrong kid":     strings.Replace(string(b), "kid-1", "kid-2", 1),
		"short key":     `{"version":1,"kid":"kid-1","priority_key":"AAAA"}`,
		"bad version":   strings.Replace(string(b), `"version":1`, `"version":2`, 1),
		"unknown field": strings.Replace(string(b), `{`, `{"x":1,`, 1),
		"trailing":      string(b) + "{}",
	} {
		if _, err := Parse([]byte(in), "kid-1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
