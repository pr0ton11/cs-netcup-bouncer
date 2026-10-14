package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pr0ton11/netcup-scp-go/scp"
)

const (
	testUser   = 1001
	testServer = 2002
	testMAC    = "02:00:00:00:00:01"
	testCopied = 3003
)

// fakeSCP serves the parts of the SCP API the bouncer uses. Like netcup, it switches the
// implicit rules to DROP_ALL while any user policy is attached. After every change it
// checks that an interface without foreign user policies still accepts ordinary traffic.
type fakeSCP struct {
	t        testing.TB
	mu       sync.Mutex
	policies map[int32]scp.FirewallPolicy
	foreign  map[int32]bool // policies of the user, not the bouncer's
	nextID   int32
	user     []int32 // attached user policies, in order
	ops      []string
	status   int  // if set, policy writes fail with it
	lenient  bool // skip the reachability check (while simulating the user's own edits)
}

func newFakeSCP(t testing.TB) *fakeSCP {
	return &fakeSCP{t: t, policies: map[int32]scp.FirewallPolicy{}, foreign: map[int32]bool{}, nextID: 500}
}

func (f *fakeSCP) addPolicy(name string, rules []scp.FirewallRule, foreign bool) int32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	f.policies[f.nextID] = scp.FirewallPolicy{Id: ptr(f.nextID), Name: ptr(name), Rules: &rules}
	f.foreign[f.nextID] = foreign
	return f.nextID
}

func (f *fakeSCP) attach(ids ...int32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.user = ids
}

func (f *fakeSCP) setRules(id int32, rules []scp.FirewallRule) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.policies[id]
	p.Rules = &rules
	f.policies[id] = p
}

func (f *fakeSCP) attached() []int32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.user)
}

func (f *fakeSCP) rules(id int32) []scp.FirewallRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	return deref(f.policies[id].Rules)
}

func (f *fakeSCP) byName(name string) int32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, p := range f.policies {
		if *p.Name == name {
			return id
		}
	}
	return 0
}

func (f *fakeSCP) implicit() scp.ImplicitRule {
	if len(f.user) > 0 {
		return scp.DROPALL
	}
	return scp.ACCEPTALL
}

// checkReachable fails the test if ordinary traffic (no banned source) would be dropped
// although none of the user's own policies is attached.
func (f *fakeSCP) checkReachable(after string) {
	if f.lenient {
		return
	}
	for _, id := range f.user {
		if f.foreign[id] {
			return
		}
	}
	for _, dir := range []scp.FirewallRuleDirection{scp.INGRESS, scp.EGRESS} {
		action := scp.FirewallAction("")
	policies:
		for _, id := range f.user {
			for _, r := range deref(f.policies[id].Rules) {
				if r.Direction == dir && r.Protocol == scp.TCP && len(deref(r.Sources)) == 0 {
					action = r.Action
					break policies
				}
			}
		}
		if action == "" && f.implicit() == scp.ACCEPTALL {
			action = scp.ACCEPT
		}
		if action != scp.ACCEPT {
			f.t.Errorf("after %s: %s TCP traffic is dropped (attached %v)", after, dir, f.user)
		}
	}
}

func (f *fakeSCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	base := fmt.Sprintf("/api/v1/users/%d/firewall-policies", testUser)
	fwPath := fmt.Sprintf("/api/v1/servers/%d/interfaces/%s/firewall", testServer, testMAC)
	var id int32
	switch {
	case r.URL.Path == base && r.Method == http.MethodGet:
		list := []scp.FirewallPolicy{}
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
		f.ops = append(f.ops, "create "+s.Name)
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
			f.ops = append(f.ops, fmt.Sprintf("put %s (%d rules)", *p.Name, len(deref(s.Rules))))
			f.checkReachable(f.ops[len(f.ops)-1])
			reply(202, scp.FirewallPolicyUpdateResult{FirewallPolicy: &p})
		}
	case r.URL.Path == fwPath && r.Method == http.MethodGet:
		var ups []scp.FirewallPolicy
		for _, id := range f.user {
			ups = append(ups, f.policies[id])
		}
		reply(200, scp.ServerFirewall{
			Active:              ptr(true),
			UserPolicies:        &ups,
			CopiedPolicies:      &[]scp.FirewallPolicy{{Id: ptr[int32](testCopied)}},
			IngressImplicitRule: ptr(f.implicit()),
			EgressImplicitRule:  ptr(f.implicit()),
		})
	case r.URL.Path == fwPath && r.Method == http.MethodPut:
		var s scp.ServerFirewallSave
		json.NewDecoder(r.Body).Decode(&s)
		if s.Active == nil || !*s.Active || len(s.CopiedPolicies) != 1 || s.CopiedPolicies[0].Id != testCopied {
			f.t.Errorf("assignment dropped the copied policy or active: %+v", s)
		}
		f.user = nil
		for _, i := range s.UserPolicies {
			f.user = append(f.user, i.Id)
		}
		f.ops = append(f.ops, fmt.Sprintf("assign %v", f.user))
		f.checkReachable(f.ops[len(f.ops)-1])
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

func (f *fakeLAPI) push(sr streamResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = append(f.queue, sr)
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

func banned(id int64, ip, dur string) streamResponse {
	return streamResponse{New: []lapiDecision{{ID: id, Type: "ban", Scope: "Ip", Value: ip, Duration: dur}}}
}

type harness struct {
	scp  *fakeSCP
	lapi *fakeLAPI
	logs *bytes.Buffer
	cfg  bouncerConfig
	fw   *netcupFirewall
	lc   *lapiClient
}

func newHarness(t *testing.T) *harness {
	h := &harness{scp: newFakeSCP(t), lapi: &fakeLAPI{}, logs: &bytes.Buffer{}}
	scpSrv := httptest.NewServer(h.scp)
	t.Cleanup(scpSrv.Close)
	lapiSrv := httptest.NewServer(h.lapi)
	t.Cleanup(lapiSrv.Close)
	api, err := scp.NewClientWithResponses(scpSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	h.fw = &netcupFirewall{api: api, userID: testUser, serverID: testServer, mac: testMAC}
	h.lc = &lapiClient{baseURL: lapiSrv.URL, apiKey: "key", http: http.DefaultClient}
	h.cfg = bouncerConfig{
		policyName:   "crowdsec-bouncer",
		policy:       policyConfig{dropProtocols: []scp.FirewallProtocol{scp.TCP, scp.UDP}, maxRules: 400},
		syncInterval: 2 * time.Minute,
		driftCheck:   time.Hour,
		clearOnExit:  true,
	}
	return h
}

func (h *harness) bouncer() *bouncer {
	return newBouncer(h.cfg, h.lc, h.fw, slog.New(slog.NewJSONHandler(h.logs, nil)))
}

// sources summarizes the DROP rules as "PROTO:addr,addr".
func sources(rules []scp.FirewallRule) []string {
	var out []string
	for _, r := range rules {
		if r.Action == scp.DROP {
			out = append(out, string(r.Protocol)+":"+strings.Join(deref(r.Sources), ","))
		}
	}
	return out
}

func TestNoUserPolicies(t *testing.T) {
	h := newHarness(t)
	h.lapi.push(banned(1, "203.0.113.1", "1h"))
	b := h.bouncer()
	ctx, now := context.Background(), time.Now()

	// First step: creates the DROP policy with the ban and the fallback, attaches both.
	b.step(ctx, now)
	drop, fallback := h.scp.byName("crowdsec-bouncer"), h.scp.byName("crowdsec-bouncer-fallback")
	if got, want := h.scp.attached(), []int32{drop, fallback}; !slices.Equal(got, want) {
		t.Fatalf("attached %v, want %v", got, want)
	}
	if got := sources(h.scp.rules(drop)); len(h.scp.rules(drop)) != 2 || !slices.Equal(got, []string{"TCP:203.0.113.1", "UDP:203.0.113.1"}) {
		t.Fatalf("DROP policy = %v", h.scp.rules(drop))
	}
	if !rulesEqual(h.scp.rules(fallback), fallbackRules()) {
		t.Fatalf("fallback = %v", h.scp.rules(fallback))
	}
	// The firewall state is logged as values, not pointers.
	if l := h.logs.String(); !strings.Contains(l, `"active":true,"ingress_implicit":"DROP_ALL","egress_implicit":"DROP_ALL"`) {
		t.Errorf("firewall log line missing values:\n%s", l)
	}

	// Nothing changed: no write. A new ban within the sync interval waits.
	ops := len(h.scp.ops)
	b.step(ctx, now.Add(30*time.Second))
	h.lapi.push(banned(2, "2001:db8::1", "3h"))
	b.step(ctx, now.Add(time.Minute))
	if len(h.scp.ops) != ops {
		t.Fatalf("wrote too early: %v", h.scp.ops[ops:])
	}
	b.step(ctx, now.Add(3*time.Minute))
	if got := sources(h.scp.rules(drop)); len(got) != 2 || !strings.Contains(got[0], "2001:db8::1") {
		t.Fatalf("DROP rules = %v", got)
	}

	// The IPv4 ban expires after an hour.
	b.step(ctx, now.Add(61*time.Minute))
	if got := sources(h.scp.rules(drop)); !slices.Equal(got, []string{"TCP:2001:db8::1", "UDP:2001:db8::1"}) {
		t.Fatalf("after expiry: %v", got)
	}

	// Changes by hand to either policy are found by the drift check and overwritten.
	h.scp.lenient = true
	h.scp.setRules(drop, nil)
	h.scp.setRules(fallback, nil)
	b.step(ctx, now.Add(125*time.Minute))
	h.scp.lenient = false
	if len(h.scp.rules(drop)) != 2 || !rulesEqual(h.scp.rules(fallback), fallbackRules()) {
		t.Fatalf("drift not corrected: drop %d, fallback %d rules", len(h.scp.rules(drop)), len(h.scp.rules(fallback)))
	}

	// Rate limited: backs off for Retry-After.
	h.scp.status = http.StatusTooManyRequests
	b.step(ctx, now.Add(200*time.Minute)) // the IPv6 ban has expired by now
	if b.backoff != 2*time.Minute {
		t.Fatalf("backoff = %s, want 2m", b.backoff)
	}
	h.scp.status = 0
	b.step(ctx, now.Add(201*time.Minute))
	if len(h.scp.rules(drop)) != 2 {
		t.Fatal("wrote during backoff")
	}
	b.step(ctx, now.Add(203*time.Minute))
	if len(h.scp.rules(drop)) != 0 {
		t.Fatalf("after backoff: %d rules", len(h.scp.rules(drop)))
	}

	// Restart: finds both policies instead of creating new ones.
	h.lapi.push(banned(3, "198.51.100.5", "1h"))
	b2 := h.bouncer()
	b2.step(ctx, now)
	if len(h.scp.policies) != 2 || h.lapi.startups != 2 || len(h.scp.rules(drop)) != 2 {
		t.Fatalf("restart: %d policies, %d startups, %d rules", len(h.scp.policies), h.lapi.startups, len(h.scp.rules(drop)))
	}
	if got, want := h.scp.attached(), []int32{drop, fallback}; !slices.Equal(got, want) {
		t.Fatalf("restart: attached %v, want %v", got, want)
	}
}

func TestForeignUserPolicies(t *testing.T) {
	h := newHarness(t)
	ssh := h.scp.addPolicy("ssh from office", []scp.FirewallRule{
		{Direction: scp.INGRESS, Protocol: scp.TCP, Action: scp.ACCEPT, DestinationPorts: ptr("22"), Sources: &[]string{"198.51.100.0/24"}},
	}, true)
	web := h.scp.addPolicy("web", []scp.FirewallRule{
		{Direction: scp.INGRESS, Protocol: scp.TCP, Action: scp.ACCEPT, DestinationPorts: ptr("443")},
	}, true)
	h.scp.attach(ssh, web)
	h.lapi.push(banned(1, "203.0.113.1", "1h"))
	b := h.bouncer()
	b.step(context.Background(), time.Now())

	drop := h.scp.byName("crowdsec-bouncer")
	if got, want := h.scp.attached(), []int32{drop, ssh, web}; !slices.Equal(got, want) {
		t.Fatalf("attached %v, want %v", got, want)
	}
	if h.scp.byName("crowdsec-bouncer-fallback") != 0 {
		t.Error("created a fallback although the user has policies")
	}
	if len(h.scp.rules(ssh)) != 1 || len(h.scp.rules(web)) != 1 {
		t.Error("changed the user's policies")
	}
}

func TestForeignPolicyAppearsLater(t *testing.T) {
	h := newHarness(t)
	h.lapi.push(banned(1, "203.0.113.1", "4h"))
	b := h.bouncer()
	ctx, now := context.Background(), time.Now()
	b.step(ctx, now)
	drop, fallback := h.scp.byName("crowdsec-bouncer"), h.scp.byName("crowdsec-bouncer-fallback")

	// The user attaches a policy of their own, wherever the SCP puts it.
	mine := h.scp.addPolicy("mine", []scp.FirewallRule{{Direction: scp.INGRESS, Protocol: scp.TCP, Action: scp.ACCEPT}}, true)
	h.scp.attach(mine, drop, fallback)
	b.step(ctx, now.Add(61*time.Minute))
	if got, want := h.scp.attached(), []int32{drop, mine}; !slices.Equal(got, want) {
		t.Fatalf("attached %v, want %v", got, want)
	}

	// And detaches it again: the fallback comes back.
	h.scp.lenient = true // the user's own detach drops traffic until the bouncer acts
	h.scp.attach(drop)
	h.scp.lenient = false
	b.step(ctx, now.Add(122*time.Minute))
	if got, want := h.scp.attached(), []int32{drop, fallback}; !slices.Equal(got, want) {
		t.Fatalf("attached %v, want %v", got, want)
	}
	if len(h.scp.policies) != 3 {
		t.Errorf("%d policies, want 3 (no second fallback)", len(h.scp.policies))
	}
}

func TestClearOnExit(t *testing.T) {
	h := newHarness(t)
	h.lapi.push(banned(1, "203.0.113.1", "1h"))
	b := h.bouncer()
	b.step(context.Background(), time.Now())
	drop, fallback := h.scp.byName("crowdsec-bouncer"), h.scp.byName("crowdsec-bouncer-fallback")

	b.clear()
	if n := len(h.scp.rules(drop)); n != 0 {
		t.Fatalf("DROP policy has %d rules after clear", n)
	}
	if got, want := h.scp.attached(), []int32{drop, fallback}; !slices.Equal(got, want) {
		t.Fatalf("attached %v, want %v", got, want)
	}
	if !rulesEqual(h.scp.rules(fallback), fallbackRules()) {
		t.Error("clear changed the fallback")
	}
}

func TestMigrationFromV010(t *testing.T) {
	h := newHarness(t)
	// v0.1.0: one policy, DROP rules followed by the accept-all rules, attached alone.
	old := append([]scp.FirewallRule{
		{Direction: scp.INGRESS, Protocol: scp.TCP, Action: scp.DROP, Sources: &[]string{"192.0.2.99"}},
	}, fallbackRules()...)
	drop := h.scp.addPolicy("crowdsec-bouncer", old, false)
	h.scp.attach(drop)
	h.lapi.push(banned(1, "203.0.113.1", "1h"))
	b := h.bouncer()
	ctx, now := context.Background(), time.Now()

	// First step: create and attach the fallback; the old policy keeps its accept rules.
	b.step(ctx, now)
	fallback := h.scp.byName("crowdsec-bouncer-fallback")
	if got, want := h.scp.attached(), []int32{drop, fallback}; !slices.Equal(got, want) {
		t.Fatalf("attached %v, want %v", got, want)
	}
	if len(h.scp.rules(drop)) != len(old) {
		t.Fatal("stripped the accept rules before the fallback was attached")
	}

	// Next step: the DROP policy is rewritten to DROP rules only.
	b.step(ctx, now.Add(30*time.Second))
	if got := sources(h.scp.rules(drop)); len(h.scp.rules(drop)) != 2 || !slices.Equal(got, []string{"TCP:203.0.113.1", "UDP:203.0.113.1"}) {
		t.Fatalf("after migration: %v", h.scp.rules(drop))
	}
	want := []string{
		"create crowdsec-bouncer-fallback",
		fmt.Sprintf("assign [%d %d]", drop, fallback),
		"put crowdsec-bouncer (2 rules)",
	}
	if !slices.Equal(h.scp.ops, want) {
		t.Fatalf("ops = %q, want %q", h.scp.ops, want)
	}
	// checkReachable ran after every write; it fails the test if traffic was ever dropped.
}

func TestAcceptOnlyIsNotOverBudget(t *testing.T) {
	h := newHarness(t)
	h.cfg.acceptOnly = true
	h.lapi.push(banned(1, "203.0.113.1", "1h"))
	b := h.bouncer()
	b.step(context.Background(), time.Now())
	l := h.logs.String()
	if !strings.Contains(l, `"active":1,"blocked":0,"over_budget":0`) || strings.Contains(l, "rule budget") {
		t.Errorf("accept-only stats wrong:\n%s", l)
	}
	if n := len(h.scp.rules(h.scp.byName("crowdsec-bouncer"))); n != 0 {
		t.Errorf("accept-only wrote %d DROP rules", n)
	}
}

func TestNoWriteBeforeFirstPull(t *testing.T) {
	h := newHarness(t)
	h.lc.apiKey = "wrong"
	b := h.bouncer()
	b.step(context.Background(), time.Now())
	if len(h.scp.ops) != 0 {
		t.Fatalf("wrote without decisions: %v", h.scp.ops)
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
