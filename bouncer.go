package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
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
	driftCheck   time.Duration // how often to read the policy and assignment back
	dryRun       bool
	acceptOnly   bool
	clearOnExit  bool
}

// bouncer keeps the netcup policy in line with the active CrowdSec bans. It rewrites the
// whole policy from the current set, so missed updates and changes made by hand are
// corrected by the next write.
type bouncer struct {
	cfg  bouncerConfig
	lapi *lapiClient
	fw   *netcupFirewall // nil in dry-run mode
	log  *slog.Logger

	set         *decisionSet
	pulled      bool // at least one successful LAPI pull
	needStartup bool

	policyID     int32
	ready        bool               // policy exists and is assigned
	applied      []scp.FirewallRule // rules last written or read back; nil if unknown
	lastWrite    time.Time
	backoff      time.Duration
	backoffUntil time.Time
	nextDrift    time.Time
	lastStats    policyStats
}

func newBouncer(cfg bouncerConfig, lapi *lapiClient, fw *netcupFirewall, log *slog.Logger) *bouncer {
	return &bouncer{cfg: cfg, lapi: lapi, fw: fw, log: log, set: newDecisionSet(), needStartup: true}
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

// step pulls new decisions and writes the policy if it is due.
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
			b.log.Info("dry run: would write policy", "name", b.cfg.policyName, "rules", len(rules), "policy", string(out))
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
		if err := b.reconcile(ctx, rules); err != nil {
			return err
		}
		b.nextDrift = now.Add(b.cfg.driftCheck)
	}
	if b.applied != nil && rulesEqual(rules, b.applied) {
		return nil
	}
	if !b.lastWrite.IsZero() && now.Sub(b.lastWrite) < b.cfg.syncInterval {
		return nil
	}
	if err := b.fw.putPolicy(ctx, b.policyID, b.save(rules)); err != nil {
		return err
	}
	b.applied, b.lastWrite = rules, now
	b.log.Info("policy written", "id", b.policyID, "rules", len(rules), "blocked", b.lastStats.blocked)
	return nil
}

// reconcile makes sure the policy exists and is assigned, and reads its rules back, so
// that the next sync corrects any change made outside the bouncer.
func (b *bouncer) reconcile(ctx context.Context, rules []scp.FirewallRule) error {
	if !b.ready {
		p, err := b.fw.findPolicy(ctx, b.cfg.policyName)
		if err != nil {
			return err
		}
		if p == nil {
			if p, err = b.fw.createPolicy(ctx, b.save(rules)); err != nil {
				return err
			}
			b.log.Info("policy created", "name", b.cfg.policyName, "id", *p.Id, "rules", len(rules))
			b.applied, b.lastWrite = rules, time.Now()
		} else {
			b.applied = deref(p.Rules)
		}
		b.policyID = *p.Id
	} else {
		p, err := b.fw.getPolicy(ctx, b.policyID)
		if err != nil {
			var ae *apiError
			if errors.As(err, &ae) && ae.status == http.StatusNotFound {
				b.log.Warn("policy disappeared; creating it again", "id", b.policyID)
				b.ready = false
				return b.reconcile(ctx, rules)
			}
			return err
		}
		if !rulesEqual(deref(p.Rules), b.applied) {
			b.log.Warn("policy was changed outside the bouncer; rewriting it", "id", b.policyID)
		}
		b.applied = deref(p.Rules)
	}

	changed, err := b.fw.ensureAssigned(ctx, b.policyID)
	if err != nil {
		return err
	}
	if changed {
		b.log.Info("policy assigned to interface", "id", b.policyID, "server", b.fw.serverID, "mac", b.fw.mac)
		if fw, err := b.fw.getFirewall(ctx); err == nil {
			b.log.Info("firewall after assignment",
				"active", fw.Active != nil && *fw.Active,
				"ingress_implicit", string(deref1(fw.IngressImplicitRule)),
				"egress_implicit", string(deref1(fw.EgressImplicitRule)),
				"user_policies", len(deref(fw.UserPolicies)), "copied_policies", len(deref(fw.CopiedPolicies)))
		}
	}
	b.ready = true
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

// clear writes the policy without DROP rules, so that no address stays on netcup's
// firewall while the bouncer is not running to lift expired bans.
func (b *bouncer) clear() {
	if b.cfg.dryRun || !b.ready {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rules, _ := buildRules(b.cfg.policy, nil, true)
	if err := b.fw.putPolicy(ctx, b.policyID, b.save(rules)); err != nil {
		b.log.Error("clear policy on exit", "err", err)
		return
	}
	b.log.Info("policy cleared on exit", "id", b.policyID)
}

func (b *bouncer) save(rules []scp.FirewallRule) scp.FirewallPolicySave {
	return scp.FirewallPolicySave{
		Name:        b.cfg.policyName,
		Description: ptr("Managed by crowdsec-netcup-bouncer. Changes are overwritten."),
		Rules:       &rules,
	}
}

func deref1[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
