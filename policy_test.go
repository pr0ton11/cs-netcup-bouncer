package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pr0ton11/netcup-scp-go/scp"
)

func TestParseBan(t *testing.T) {
	now := time.Unix(1000, 0)
	tests := []struct {
		d    lapiDecision
		want string
		err  bool
	}{
		{lapiDecision{Type: "ban", Scope: "Ip", Value: "203.0.113.7", Duration: "4h"}, "203.0.113.7/32", false},
		{lapiDecision{Type: "ban", Scope: "Ip", Value: "::ffff:203.0.113.7", Duration: "4h"}, "203.0.113.7/32", false},
		{lapiDecision{Type: "ban", Scope: "Range", Value: "198.51.100.9/24", Duration: "1h"}, "198.51.100.0/24", false},
		{lapiDecision{Type: "ban", Scope: "Ip", Value: "2001:db8::1", Duration: "1h"}, "2001:db8::1/128", false},
		{lapiDecision{Type: "captcha", Scope: "Ip", Value: "203.0.113.7", Duration: "4h"}, "", true},
		{lapiDecision{Type: "ban", Scope: "Country", Value: "CH", Duration: "4h"}, "", true},
		{lapiDecision{Type: "ban", Scope: "Ip", Value: "nope", Duration: "4h"}, "", true},
	}
	for _, tt := range tests {
		b, err := parseBan(tt.d, now)
		if (err != nil) != tt.err {
			t.Errorf("%+v: err = %v", tt.d, err)
			continue
		}
		if err == nil && b.prefix.String() != tt.want {
			t.Errorf("%+v: got %s, want %s", tt.d, b.prefix, tt.want)
		}
	}
}

func TestDecisionSet(t *testing.T) {
	now := time.Unix(1000, 0)
	s := newDecisionSet()
	s.apply(&streamResponse{New: []lapiDecision{
		{ID: 1, Type: "ban", Scope: "Ip", Value: "203.0.113.1", Duration: "1h"},
		{ID: 2, Type: "ban", Scope: "Ip", Value: "203.0.113.1", Duration: "3h"}, // same IP, longer
		{ID: 3, Type: "ban", Scope: "Ip", Value: "203.0.113.2", Duration: "2h"},
		{ID: 4, Type: "ban", Scope: "Ip", Value: "192.0.2.10", Duration: "2h"},   // never block
		{ID: 5, Type: "ban", Scope: "Ip", Value: "10.0.0.1", Duration: "2h"},     // private
		{ID: 6, Type: "ban", Scope: "Range", Value: "0.0.0.0/0", Duration: "2h"}, // too wide
		{ID: 7, Type: "ban", Scope: "Ip", Value: "203.0.113.3", Duration: "10m"},
	}}, true, now)

	never := []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")}
	got := prefixes(s.active(now, never))
	if want := "203.0.113.1/32 203.0.113.2/32 203.0.113.3/32"; got != want {
		t.Fatalf("active = %s, want %s", got, want)
	}

	// Expiry and deletion both remove entries.
	s.apply(&streamResponse{Deleted: []lapiDecision{{ID: 3}}}, false, now)
	if got, want := prefixes(s.active(now.Add(30*time.Minute), never)), "203.0.113.1/32"; got != want {
		t.Fatalf("after delete/expiry = %s, want %s", got, want)
	}
	if _, ok := s.byID[7]; ok {
		t.Error("expired decision still held")
	}

	// A startup pull replaces the set.
	s.apply(&streamResponse{New: []lapiDecision{{ID: 9, Type: "ban", Scope: "Ip", Value: "198.51.100.1", Duration: "1h"}}}, true, now)
	if got, want := prefixes(s.active(now, never)), "198.51.100.1/32"; got != want {
		t.Fatalf("after startup = %s, want %s", got, want)
	}
}

func prefixes(bans []ban) string {
	var s []string
	for _, b := range bans {
		s = append(s, b.prefix.String())
	}
	return strings.Join(s, " ")
}

func TestRulesEqualNormalizes(t *testing.T) {
	a := []scp.FirewallRule{{Direction: scp.INGRESS, Protocol: scp.TCP, Action: scp.DROP, Sources: &[]string{"203.0.113.2", "203.0.113.1"}}}
	b := []scp.FirewallRule{{Direction: scp.INGRESS, Protocol: scp.TCP, Action: scp.DROP, Sources: &[]string{"203.0.113.1/32", "203.0.113.2"},
		NumberOfEffectiveRules: ptr[int32](2), DestinationPorts: ptr(""), Destinations: &[]string{}}}
	if !rulesEqual(a, b) {
		t.Error("equal rules compare different")
	}
	b[0].Action = scp.ACCEPT
	if rulesEqual(a, b) {
		t.Error("different rules compare equal")
	}
}

// fakeSCP serves the parts of the SCP API the bouncer uses.

func TestBuildRules(t *testing.T) {
	cfg := policyConfig{dropProtocols: []scp.FirewallProtocol{scp.TCP, scp.UDP}, maxRules: 2 * 150} // room for 150
	now := time.Unix(1000, 0)
	var bans []ban
	for i := range 200 {
		bans = append(bans, ban{
			prefix:  netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, byte(i / 256), byte(i)}), 32),
			expires: now.Add(time.Duration(200-i) * time.Minute), // earlier ones last longer
		})
	}
	rules, st := buildRules(cfg, bans, false)
	if st.active != 200 || st.blocked != 150 || st.dropped != 50 {
		t.Fatalf("stats = %+v", st)
	}
	// TCP 100 + 50, UDP 100 + 50, and nothing else.
	if len(rules) != 4 {
		t.Fatalf("got %d rules", len(rules))
	}
	cost := 0
	for i, r := range rules {
		cost += len(*r.Sources)
		if r.Action != scp.DROP || r.Direction != scp.INGRESS {
			t.Errorf("rule %d: want INGRESS DROP, got %s %s", i, r.Direction, r.Action)
		}
	}
	if cost > cfg.maxRules {
		t.Errorf("cost %d over budget %d", cost, cfg.maxRules)
	}
	// The longest-lasting bans are kept: 203.0.0.0 .. 203.0.0.149.
	src := *rules[1].Sources
	if src[len(src)-1] != "203.0.0.149" || (*rules[0].Sources)[0] != "203.0.0.0" {
		t.Errorf("wrong selection: first %s, last %s", (*rules[0].Sources)[0], src[len(src)-1])
	}

	// ACCEPT_ONLY blocks nothing, and that is not over budget.
	rules, st = buildRules(cfg, bans, true)
	if len(rules) != 0 || st != (policyStats{active: 200}) {
		t.Fatalf("accept only: %d rules, %+v", len(rules), st)
	}
}
