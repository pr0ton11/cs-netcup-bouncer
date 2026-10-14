package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/pr0ton11/netcup-scp-go/scp"
)

const (
	minBackoff = time.Minute
	maxBackoff = 30 * time.Minute
)

type bouncerConfig struct {
	policyName   string
	policy       policyConfig
	pollInterval time.Duration // how often to pull the LAPI
	syncInterval time.Duration // minimum time between policy writes
	driftCheck   time.Duration // how often to read the policies and assignment back
	dryRun       bool
	acceptOnly   bool
	clearOnExit  bool
}

func (c bouncerConfig) fallbackName() string { return c.policyName + "-fallback" }

// bouncer keeps the netcup firewall in line with the active CrowdSec bans. It owns two
// user policies:
//
//   - the DROP policy holds only INGRESS DROP rules for the bans and is attached first;
//   - the fallback policy accepts everything and is attached last, but only while the
//     interface has no other user policy. Attaching any user policy switches netcup's
//     implicit rules to DROP_ALL; the fallback restores what the interface did before.
//
// The user's own policies stay attached, in their order, between the two. The bouncer
// rewrites the whole DROP policy from the current set, so missed updates and changes made
// by hand are corrected by the next write.
type bouncer struct {
	cfg  bouncerConfig
	lapi *lapiClient
	fw   *netcupFirewall // nil in dry-run mode
	log  *slog.Logger

	set         *decisionSet
	pulled      bool // at least one successful LAPI pull
	needStartup bool

	dropID       int32
	fallbackID   int32              // 0 if the fallback policy does not exist (yet)
	ready        bool               // DROP policy exists and the assignment is as wanted
	applied      []scp.FirewallRule // DROP rules last written or read back; nil if unknown
	lastWrite    time.Time
	backoff      time.Duration
	backoffUntil time.Time
	nextDrift    time.Time
	lastStats    policyStats
}

func newBouncer(cfg bouncerConfig, lapi *lapiClient, fw *netcupFirewall, log *slog.Logger) *bouncer {
	return &bouncer{cfg: cfg, lapi: lapi, fw: fw, log: log, set: newDecisionSet(lapi.origins), needStartup: true}
}

func (b *bouncer) run(ctx context.Context) error {
	t := time.NewTicker(b.cfg.pollInterval)
	defer t.Stop()
	for {
		b.step(ctx, time.Now())
		select {
		case <-ctx.Done():
			if b.cfg.clearOnExit {
				b.clear()
			}
			return nil
		case <-t.C:
		}
	}
}

// step pulls new decisions and writes the policies if it is due.
func (b *bouncer) step(ctx context.Context, now time.Time) {
	b.pull(ctx, now)
	if !b.pulled {
		// Writing before the first pull would lift every existing block.
		return
	}
	rules, st := buildRules(b.cfg.policy, b.set.active(now, b.cfg.policy.neverBlock), b.cfg.acceptOnly)
	if st != b.lastStats {
		b.log.Info("decisions", "active", st.active, "blocked", st.blocked, "over_budget", st.dropped)
		if st.dropped > 0 && b.lastStats.dropped == 0 {
			b.log.Warn("more bans than the rule budget allows; keeping the longest-lasting", "max_blocked", b.cfg.policy.maxBlocked())
		}
		b.lastStats = st
	}

	if b.cfg.dryRun {
		if b.applied == nil || !rulesEqual(rules, b.applied) {
			out, _ := json.Marshal(redactRules(rules))
			b.log.Info("dry run: would write DROP policy", "name", b.cfg.policyName, "rules", len(rules), "policy", string(out))
			b.applied = rules
		}
		return
	}

	if now.Before(b.backoffUntil) {
		return
	}
	if err := b.sync(ctx, now, rules); err != nil {
		b.fail(now, err)
		return
	}
	b.backoff = 0
}

func (b *bouncer) pull(ctx context.Context, now time.Time) {
	startup := b.needStartup
	sr, err := b.lapi.stream(ctx, startup)
	if err != nil {
		if ctx.Err() == nil {
			b.log.Error("pull decisions", "err", err)
		}
		// Start over with the full set, in case the LAPI lost track of this bouncer.
		b.needStartup = true
		return
	}
	skipped := b.set.apply(sr, startup, now)
	if startup || len(sr.New) > 0 || len(sr.Deleted) > 0 {
		b.log.Debug("pulled decisions", "startup", startup, "new", len(sr.New), "deleted", len(sr.Deleted), "skipped", skipped)
	}
	b.needStartup = false
	b.pulled = true
}

func (b *bouncer) sync(ctx context.Context, now time.Time, rules []scp.FirewallRule) error {
	if !b.ready || !now.Before(b.nextDrift) {
		reassigned, err := b.reconcile(ctx, rules)
		if err != nil {
			return err
		}
		b.nextDrift = now.Add(b.cfg.driftCheck)
		if reassigned {
			// Let netcup apply the new assignment before the DROP policy changes. When
			// moving from a v0.1.0 policy that still holds the accept rules, this attaches
			// the fallback before those rules go away.
			return nil
		}
	}
	if b.applied != nil && rulesEqual(rules, b.applied) {
		return nil
	}
	if !b.lastWrite.IsZero() && now.Sub(b.lastWrite) < b.cfg.syncInterval {
		return nil
	}
	if err := b.fw.putPolicy(ctx, b.dropID, b.dropSave(rules)); err != nil {
		return err
	}
	b.applied, b.lastWrite = rules, now
	b.log.Info("DROP policy written", "id", b.dropID, "rules", len(rules), "blocked", b.lastStats.blocked)
	return nil
}

// reconcile makes sure the DROP policy exists, reads its rules back so that the next sync
// corrects changes made outside the bouncer, and fixes the assignment. It reports whether
// it changed the assignment.
func (b *bouncer) reconcile(ctx context.Context, rules []scp.FirewallRule) (bool, error) {
	if err := b.reconcileDrop(ctx, rules); err != nil {
		return false, err
	}
	if b.fallbackID == 0 {
		// After a restart, the fallback may already exist and be attached.
		p, err := b.fw.findPolicy(ctx, b.cfg.fallbackName())
		if err != nil {
			return false, err
		}
		if p != nil {
			b.fallbackID = *p.Id
		}
	}

	fw, err := b.fw.getFirewall(ctx)
	if err != nil {
		return false, err
	}
	current := policyIDs(fw.UserPolicies)
	var foreign []int32
	for _, id := range current {
		if id != b.dropID && id != b.fallbackID {
			foreign = append(foreign, id)
		}
	}
	want := append([]int32{b.dropID}, foreign...)
	if len(foreign) == 0 {
		if err := b.reconcileFallback(ctx); err != nil {
			return false, err
		}
		want = append(want, b.fallbackID)
	}
	if slices.Equal(current, want) {
		b.ready = true
		return false, nil
	}

	if err := b.fw.putAssignment(ctx, fw, want); err != nil {
		return false, err
	}
	b.log.Info("policies assigned to interface", "server", b.fw.serverID, "mac", b.fw.mac,
		"drop_policy", b.dropID, "other_user_policies", len(foreign), "fallback", len(foreign) == 0)
	if fw, err := b.fw.getFirewall(ctx); err == nil {
		b.logFirewall(fw)
	}
	b.ready = true
	return true, nil
}

func (b *bouncer) logFirewall(fw *scp.ServerFirewall) {
	b.log.Info("firewall after assignment",
		"active", fw.Active != nil && *fw.Active,
		"ingress_implicit", string(deref1(fw.IngressImplicitRule)),
		"egress_implicit", string(deref1(fw.EgressImplicitRule)),
		"user_policies", len(deref(fw.UserPolicies)), "copied_policies", len(deref(fw.CopiedPolicies)))
}

func (b *bouncer) reconcileDrop(ctx context.Context, rules []scp.FirewallRule) error {
	if b.dropID == 0 {
		p, err := b.fw.findPolicy(ctx, b.cfg.policyName)
		if err != nil {
			return err
		}
		if p == nil {
			if p, err = b.fw.createPolicy(ctx, b.dropSave(rules)); err != nil {
				return err
			}
			b.log.Info("DROP policy created", "name", b.cfg.policyName, "id", *p.Id, "rules", len(rules))
			b.applied, b.lastWrite = rules, time.Now()
		} else {
			b.applied = deref(p.Rules)
		}
		b.dropID = *p.Id
		return nil
	}
	p, err := b.fw.getPolicy(ctx, b.dropID)
	if err != nil {
		if isNotFound(err) {
			b.log.Warn("DROP policy disappeared; creating it again", "id", b.dropID)
			b.dropID, b.ready = 0, false
			return b.reconcileDrop(ctx, rules)
		}
		return err
	}
	if !rulesEqual(deref(p.Rules), b.applied) {
		b.log.Warn("DROP policy was changed outside the bouncer; rewriting it", "id", b.dropID)
	}
	b.applied = deref(p.Rules)
	return nil
}

// reconcileFallback makes sure the fallback policy exists and accepts everything.
func (b *bouncer) reconcileFallback(ctx context.Context) error {
	want := fallbackRules()
	save := scp.FirewallPolicySave{
		Name:        b.cfg.fallbackName(),
		Description: ptr("Managed by crowdsec-netcup-bouncer: accepts all while no other user policy is attached."),
		Rules:       &want,
	}
	if b.fallbackID != 0 {
		p, err := b.fw.getPolicy(ctx, b.fallbackID)
		switch {
		case err == nil:
			if rulesEqual(deref(p.Rules), want) {
				return nil
			}
			b.log.Warn("fallback policy was changed outside the bouncer; rewriting it", "id", b.fallbackID)
			return b.fw.putPolicy(ctx, b.fallbackID, save)
		case isNotFound(err):
			b.fallbackID = 0
		default:
			return err
		}
	}
	p, err := b.fw.createPolicy(ctx, save)
	if err != nil {
		return err
	}
	b.fallbackID = *p.Id
	b.log.Info("fallback policy created", "name", save.Name, "id", b.fallbackID)
	return nil
}

func (b *bouncer) fail(now time.Time, err error) {
	b.backoff = min(max(2*b.backoff, minBackoff), maxBackoff)
	var ae *apiError
	if errors.As(err, &ae) && ae.retryAfter > b.backoff {
		b.backoff = min(ae.retryAfter, maxBackoff)
	}
	b.backoffUntil = now.Add(b.backoff)
	b.log.Error("netcup sync failed", "err", err, "retry_in", b.backoff)
}

// clear empties the DROP policy, so that no address stays on netcup's firewall while the
// bouncer is not running to lift expired bans. The fallback stays attached.
func (b *bouncer) clear() {
	if b.cfg.dryRun || b.dropID == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := b.fw.putPolicy(ctx, b.dropID, b.dropSave(nil)); err != nil {
		b.log.Error("clear DROP policy on exit", "err", err)
		return
	}
	b.log.Info("DROP policy cleared on exit", "id", b.dropID)
}

func (b *bouncer) dropSave(rules []scp.FirewallRule) scp.FirewallPolicySave {
	if rules == nil {
		rules = []scp.FirewallRule{}
	}
	return scp.FirewallPolicySave{
		Name:        b.cfg.policyName,
		Description: ptr("Managed by crowdsec-netcup-bouncer: blocks CrowdSec bans. Changes are overwritten."),
		Rules:       &rules,
	}
}

func isNotFound(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.status == http.StatusNotFound
}

func deref1[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
