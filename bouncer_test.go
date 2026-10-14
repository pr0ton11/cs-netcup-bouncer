package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
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

func TestBuildRules(t *testing.T) {
	cfg := policyConfig{
		accept:        defaultAcceptRules(),
		dropProtocols: []scp.FirewallProtocol{scp.TCP, scp.UDP},
		maxRules:      8 + 2*150, // room for 150 addresses
	}
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
	// TCP 100 + 50, UDP 100 + 50, then the 8 ACCEPT rules.
	if len(rules) != 4+8 {
		t.Fatalf("got %d rules", len(rules))
	}
	cost := 0
	for i, r := range rules {
		cost += ruleCost(r)
		if i < 4 && (r.Action != scp.DROP || r.Direction != scp.INGRESS) {
			t.Errorf("rule %d: want INGRESS DROP, got %s %s", i, r.Direction, r.Action)
		}
		if i >= 4 && r.Action != scp.ACCEPT {
			t.Errorf("rule %d: want ACCEPT, got %s", i, r.Action)
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

	rules, st = buildRules(cfg, bans, true)
	if len(rules) != 8 || st != (policyStats{active: 200}) {
		t.Fatalf("accept only: %d rules, %+v", len(rules), st)
	}
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
type fakeSCP struct {
	mu       sync.Mutex
	policies map[int32]scp.FirewallPolicy
	nextID   int32
	firewall scp.ServerFirewall
	puts     int
	assigns  []scp.ServerFirewallSave
	status   int // if set, policy writes fail with it
}

func (f *fakeSCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	const base = "/api/v1/users/1001/firewall-policies"
	fwPath := "/api/v1/servers/2002/interfaces/02:00:00:00:00:01/firewall"
	var id int32
	switch {
	case r.URL.Path == base && r.Method == http.MethodGet:
		var list []scp.FirewallPolicy
		for _, p := range f.policies {
			if strings.Contains(*p.Name, r.URL.Query().Get("q")) {
				list = append(list, scp.FirewallPolicy{Id: p.Id, Name: p.Name})
			}
		}
		reply(200, list)
	case r.URL.Path == base && r.Method == http.MethodPost:
		var s scp.FirewallPolicySave
		json.NewDecoder(r.Body).Decode(&s)
		f.nextID++
		p := scp.FirewallPolicy{Id: ptr(f.nextID), Name: &s.Name, Description: s.Description, Rules: s.Rules}
		f.policies[f.nextID] = p
		reply(201, p)
	case func() bool { _, err := fmt.Sscanf(r.URL.Path, base+"/%d", &id); return err == nil }():
		p, ok := f.policies[id]
		if !ok {
			reply(404, map[string]string{"message": "not found"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			reply(200, p)
		case http.MethodPut:
			if f.status != 0 {
				w.Header().Set("Retry-After", "120")
				reply(f.status, map[string]string{"message": "nope"})
				return
			}
			var s scp.FirewallPolicySave
			json.NewDecoder(r.Body).Decode(&s)
			p.Rules = s.Rules
			f.policies[id] = p
			f.puts++
			reply(202, scp.FirewallPolicyUpdateResult{FirewallPolicy: &p})
		}
	case r.URL.Path == fwPath && r.Method == http.MethodGet:
		reply(200, f.firewall)
	case r.URL.Path == fwPath && r.Method == http.MethodPut:
		var s scp.ServerFirewallSave
		json.NewDecoder(r.Body).Decode(&s)
		f.assigns = append(f.assigns, s)
		var ups []scp.FirewallPolicy
		for _, i := range s.UserPolicies {
			ups = append(ups, scp.FirewallPolicy{Id: ptr(i.Id)})
		}
		f.firewall.UserPolicies = &ups
		reply(202, scp.TaskInfo{})
	default:
		reply(404, map[string]string{"message": r.Method + " " + r.URL.Path})
	}
}

// fakeLAPI serves /v1/decisions/stream with the queued responses.
type fakeLAPI struct {
	mu       sync.Mutex
	queue    []streamResponse
	startups int
}

func (f *fakeLAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-Api-Key") != "key" {
		w.WriteHeader(403)
		return
	}
	if r.URL.Query().Get("startup") == "true" {
		f.startups++
	}
	sr := streamResponse{}
	if len(f.queue) > 0 {
		sr, f.queue = f.queue[0], f.queue[1:]
	}
	json.NewEncoder(w).Encode(sr)
}

func TestBouncerEndToEnd(t *testing.T) {
	scpFake := &fakeSCP{policies: map[int32]scp.FirewallPolicy{}, nextID: 500, firewall: scp.ServerFirewall{
		Active:              ptr(true),
		CopiedPolicies:      &[]scp.FirewallPolicy{{Id: ptr[int32](3003)}},
		IngressImplicitRule: ptr(scp.ACCEPTALL),
	}}
	scpSrv := httptest.NewServer(scpFake)
	defer scpSrv.Close()
	lapiFake := &fakeLAPI{queue: []streamResponse{
		{New: []lapiDecision{{ID: 1, Type: "ban", Scope: "Ip", Value: "203.0.113.1", Duration: "1h"}}},
		{},
		{New: []lapiDecision{{ID: 2, Type: "ban", Scope: "Ip", Value: "2001:db8::1", Duration: "3h"}}},
	}}
	lapiSrv := httptest.NewServer(lapiFake)
	defer lapiSrv.Close()

	api, err := scp.NewClientWithResponses(scpSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	b := newBouncer(bouncerConfig{
		policyName: "crowdsec-bouncer",
		policy: policyConfig{
			accept: defaultAcceptRules(), dropProtocols: []scp.FirewallProtocol{scp.TCP, scp.UDP}, maxRules: 400,
		},
		syncInterval: 2 * time.Minute,
		driftCheck:   time.Hour,
	},
		&lapiClient{baseURL: lapiSrv.URL, apiKey: "key", http: http.DefaultClient},
		&netcupFirewall{api: api, userID: 1001, serverID: 2002, mac: "02:00:00:00:00:01"},
		slog.New(slog.NewJSONHandler(logs, nil)))

	ctx := context.Background()
	now := time.Now()

	// First step: creates the policy with the ban and assigns it, keeping the copied policy.
	b.step(ctx, now)
	if len(scpFake.policies) != 1 || len(scpFake.assigns) != 1 {
		t.Fatalf("policies %d, assigns %d", len(scpFake.policies), len(scpFake.assigns))
	}
	as := scpFake.assigns[0]
	if len(as.UserPolicies) != 1 || as.UserPolicies[0].Id != 501 || len(as.CopiedPolicies) != 1 || as.CopiedPolicies[0].Id != 3003 || !*as.Active {
		t.Fatalf("assignment = %+v", as)
	}
	p := scpFake.policies[501]
	if r := (*p.Rules)[0]; r.Action != scp.DROP || (*r.Sources)[0] != "203.0.113.1" {
		t.Fatalf("first rule = %+v", r)
	}
	// The firewall state is logged as values, not pointers.
	if l := logs.String(); !strings.Contains(l, `"active":true,"ingress_implicit":"ACCEPT_ALL","egress_implicit":""`) {
		t.Errorf("firewall log line missing values:\n%s", l)
	}

	// Nothing changed: no write.
	b.step(ctx, now.Add(30*time.Second))
	if scpFake.puts != 0 {
		t.Fatalf("puts = %d, want 0", scpFake.puts)
	}

	// A new ban within the sync interval waits, then gets written.
	b.step(ctx, now.Add(time.Minute))
	if scpFake.puts != 0 {
		t.Fatalf("wrote within sync interval")
	}
	b.step(ctx, now.Add(3*time.Minute))
	if scpFake.puts != 1 || len(*scpFake.policies[501].Rules) != 2+8 {
		t.Fatalf("puts = %d, rules = %d", scpFake.puts, len(*scpFake.policies[501].Rules))
	}

	// The IPv4 ban expires after an hour and is removed; the drift check finds no change.
	b.step(ctx, now.Add(61*time.Minute))
	rules := *scpFake.policies[501].Rules
	if scpFake.puts != 2 || len(rules) != 2+8 || (*rules[0].Sources)[0] != "2001:db8::1" || len(*rules[0].Sources) != 1 {
		t.Fatalf("after expiry: puts %d, rules %+v", scpFake.puts, rules)
	}
	if len(scpFake.assigns) != 1 {
		t.Fatalf("reassigned although still assigned")
	}

	// A change by hand is found by the drift check and overwritten.
	scpFake.mu.Lock()
	p = scpFake.policies[501]
	p.Rules = &[]scp.FirewallRule{}
	scpFake.policies[501] = p
	scpFake.mu.Unlock()
	b.step(ctx, now.Add(125*time.Minute))
	if scpFake.puts != 3 || len(*scpFake.policies[501].Rules) != 2+8 {
		t.Fatalf("drift not corrected: puts %d", scpFake.puts)
	}

	// Rate limited: backs off for Retry-After.
	scpFake.status = http.StatusTooManyRequests
	b.step(ctx, now.Add(200*time.Minute)) // the IPv6 ban has expired by now
	if b.backoff != 2*time.Minute {
		t.Fatalf("backoff = %s, want 2m", b.backoff)
	}
	scpFake.status = 0
	b.step(ctx, now.Add(201*time.Minute))
	if scpFake.puts != 3 {
		t.Fatalf("wrote during backoff")
	}
	b.step(ctx, now.Add(203*time.Minute))
	if scpFake.puts != 4 || len(*scpFake.policies[501].Rules) != 8 {
		t.Fatalf("after backoff: puts %d, rules %d", scpFake.puts, len(*scpFake.policies[501].Rules))
	}

	// Restart: finds the existing policy instead of creating a second one.
	lapiFake.queue = []streamResponse{{New: []lapiDecision{{ID: 3, Type: "ban", Scope: "Ip", Value: "198.51.100.5", Duration: "1h"}}}}
	b2 := newBouncer(b.cfg, b.lapi, b.fw, b.log)
	b2.step(ctx, now)
	if len(scpFake.policies) != 1 || scpFake.puts != 5 || lapiFake.startups != 2 {
		t.Fatalf("restart: policies %d, puts %d, startups %d", len(scpFake.policies), scpFake.puts, lapiFake.startups)
	}

	// Exit clears the DROP rules.
	b2.clear()
	if len(*scpFake.policies[501].Rules) != 8 {
		t.Fatalf("clear left %d rules", len(*scpFake.policies[501].Rules))
	}
}

func TestNoWriteBeforeFirstPull(t *testing.T) {
	lapiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer lapiSrv.Close()
	scpFake := &fakeSCP{policies: map[int32]scp.FirewallPolicy{}}
	scpSrv := httptest.NewServer(scpFake)
	defer scpSrv.Close()
	api, _ := scp.NewClientWithResponses(scpSrv.URL)
	b := newBouncer(bouncerConfig{policyName: "x", policy: policyConfig{accept: defaultAcceptRules(), dropProtocols: []scp.FirewallProtocol{scp.TCP}, maxRules: 100}},
		&lapiClient{baseURL: lapiSrv.URL, apiKey: "key", http: http.DefaultClient},
		&netcupFirewall{api: api, userID: 1001, serverID: 2002, mac: "02:00:00:00:00:01"},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.step(context.Background(), time.Now())
	if len(scpFake.policies) != 0 {
		t.Fatal("created a policy without decisions")
	}
}

func TestLoadAcceptRulesExample(t *testing.T) {
	rules, err := loadAcceptRules("deploy/accept-rules.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 10 || *rules[0].DestinationPorts != "22" {
		t.Fatalf("got %d rules", len(rules))
	}
}

func TestLogFormat(t *testing.T) {
	for _, tt := range []struct {
		format string
		ok     bool
	}{{"", true}, {"json", true}, {"text", true}, {"logfmt", false}} {
		t.Setenv("LOG_FORMAT", tt.format)
		if _, err := newLogger(); (err == nil) != tt.ok {
			t.Errorf("LOG_FORMAT=%q: err = %v", tt.format, err)
		}
	}
	t.Setenv("LOG_FORMAT", "")
	l, _ := newLogger()
	if _, ok := l.Handler().(*slog.JSONHandler); !ok {
		t.Errorf("default handler is %T, want JSON", l.Handler())
	}
}
