package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"

	"github.com/pr0ton11/netcup-scp-go/scp"
)

// maxSourcesPerRule is netcup's limit of addresses in one rule.
const maxSourcesPerRule = 100

// policyConfig describes the DROP policy the bouncer keeps on the netcup firewall.
type policyConfig struct {
	dropProtocols []scp.FirewallProtocol
	// maxRules is the budget of effective rules for the DROP policy.
	maxRules   int
	neverBlock []netip.Prefix
}

// fallbackRules accept all traffic in both directions. They make up the fallback policy,
// which keeps the interface behaving as with ACCEPT_ALL while the DROP policy is the only
// user policy: attaching any user policy switches the implicit rules to DROP_ALL.
func fallbackRules() []scp.FirewallRule {
	var rules []scp.FirewallRule
	for _, dir := range []scp.FirewallRuleDirection{scp.INGRESS, scp.EGRESS} {
		for _, proto := range []scp.FirewallProtocol{scp.TCP, scp.UDP, scp.ICMP, scp.ICMPv6} {
			rules = append(rules, scp.FirewallRule{
				Direction:   dir,
				Protocol:    proto,
				Action:      scp.ACCEPT,
				Description: ptr(fmt.Sprintf("allow %s %s", dir, proto)),
			})
		}
	}
	return rules
}

// maxBlocked is how many prefixes fit into the DROP rules. netcup counts every source
// address of a rule as one rule.
func (c policyConfig) maxBlocked() int {
	return c.maxRules / len(c.dropProtocols)
}

type policyStats struct {
	active, blocked, dropped int
}

// buildRules returns the DROP rules for the bans. bans must be ordered by priority; the
// ones beyond the budget are left out. With acceptOnly, it returns no rules, and no ban
// counts as over budget.
func buildRules(c policyConfig, bans []ban, acceptOnly bool) ([]scp.FirewallRule, policyStats) {
	st := policyStats{active: len(bans)}
	if acceptOnly {
		return nil, st
	}
	if n := c.maxBlocked(); len(bans) > n {
		bans = bans[:n]
	}
	st.blocked = len(bans)
	st.dropped = st.active - st.blocked

	prefixes := make([]netip.Prefix, len(bans))
	for i, b := range bans {
		prefixes[i] = b.prefix
	}
	// Sorted by address, so that rules only change when the set changes.
	slices.SortFunc(prefixes, comparePrefix)

	var rules []scp.FirewallRule
	for _, proto := range c.dropProtocols {
		for chunk := range slices.Chunk(prefixes, maxSourcesPerRule) {
			sources := make([]string, len(chunk))
			for i, p := range chunk {
				sources[i] = prefixString(p)
			}
			rules = append(rules, scp.FirewallRule{
				Direction:   scp.INGRESS,
				Protocol:    proto,
				Action:      scp.DROP,
				Sources:     &sources,
				Description: ptr(fmt.Sprintf("crowdsec ban %s (%d)", proto, len(chunk))),
			})
		}
	}
	return rules, st
}

// prefixString writes a single address without its prefix length.
func prefixString(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// normalizeRules returns rules in a canonical form, so that rules read back from netcup
// compare equal to the ones the bouncer wrote.
func normalizeRules(rules []scp.FirewallRule) []scp.FirewallRule {
	out := make([]scp.FirewallRule, len(rules))
	for i, r := range rules {
		r.NumberOfEffectiveRules = nil
		r.Sources = normalizeAddrs(r.Sources)
		r.Destinations = normalizeAddrs(r.Destinations)
		if r.SourcePorts != nil && *r.SourcePorts == "" {
			r.SourcePorts = nil
		}
		if r.DestinationPorts != nil && *r.DestinationPorts == "" {
			r.DestinationPorts = nil
		}
		if r.Description != nil && *r.Description == "" {
			r.Description = nil
		}
		out[i] = r
	}
	return out
}

func normalizeAddrs(addrs *[]string) *[]string {
	if addrs == nil || len(*addrs) == 0 {
		return nil
	}
	out := make([]string, len(*addrs))
	for i, s := range *addrs {
		if p, err := netip.ParsePrefix(s); err == nil {
			s = prefixString(p.Masked())
		} else if a, err := netip.ParseAddr(s); err == nil {
			s = a.String()
		}
		out[i] = s
	}
	slices.Sort(out)
	return &out
}

func rulesEqual(a, b []scp.FirewallRule) bool {
	ja, err1 := json.Marshal(normalizeRules(a))
	jb, err2 := json.Marshal(normalizeRules(b))
	return err1 == nil && err2 == nil && string(ja) == string(jb)
}

// redactRules replaces the addresses in DROP rules with their count, for logging without
// IP addresses.
func redactRules(rules []scp.FirewallRule) []scp.FirewallRule {
	out := slices.Clone(rules)
	for i, r := range out {
		if r.Action == scp.DROP && r.Sources != nil {
			out[i].Sources = &[]string{fmt.Sprintf("<%d addresses>", len(*r.Sources))}
		}
	}
	return out
}

func ptr[T any](v T) *T { return &v }
