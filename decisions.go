package main

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Prefixes wider than these are never blocked, so that a mistaken range decision cannot
// cut off a large part of the internet (or the admin).
const (
	minPrefixV4 = 16
	minPrefixV6 = 32
)

type ban struct {
	prefix  netip.Prefix
	expires time.Time
}

// decisionSet holds the active ban decisions, in memory only. Entries leave the set when
// the LAPI deletes them or when they expire, whichever comes first.
type decisionSet struct {
	byID map[int64]ban
	// origins, if not empty, holds the only origins whose decisions are kept. The LAPI
	// filters on them too; this keeps a LAPI that ignores the filter from filling the
	// rule budget.
	origins map[string]bool
}

func newDecisionSet(origins []string) *decisionSet {
	s := &decisionSet{byID: map[int64]ban{}}
	if len(origins) > 0 {
		s.origins = map[string]bool{}
		for _, o := range origins {
			s.origins[o] = true
		}
	}
	return s
}

// apply merges a stream response into the set. With startup set, it replaces the set.
// It returns the number of decisions it skipped because they are not IP bans or come
// from an origin that is not wanted.
func (s *decisionSet) apply(sr *streamResponse, startup bool, now time.Time) (skipped int) {
	if startup {
		clear(s.byID)
	}
	for _, d := range sr.Deleted {
		delete(s.byID, d.ID)
	}
	for _, d := range sr.New {
		if s.origins != nil && !s.origins[d.Origin] {
			skipped++
			continue
		}
		b, err := parseBan(d, now)
		if err != nil {
			skipped++
			continue
		}
		s.byID[d.ID] = b
	}
	return skipped
}

func parseBan(d lapiDecision, now time.Time) (ban, error) {
	if !strings.EqualFold(d.Type, "ban") {
		return ban{}, fmt.Errorf("decision type %q", d.Type)
	}
	dur, err := time.ParseDuration(d.Duration)
	if err != nil {
		return ban{}, fmt.Errorf("duration %q: %w", d.Duration, err)
	}
	var p netip.Prefix
	switch strings.ToLower(d.Scope) {
	case "ip":
		a, err := netip.ParseAddr(d.Value)
		if err != nil {
			return ban{}, err
		}
		a = a.Unmap()
		p = netip.PrefixFrom(a, a.BitLen())
	case "range":
		p, err = netip.ParsePrefix(d.Value)
		if err != nil {
			return ban{}, err
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		p = p.Masked()
	default:
		return ban{}, fmt.Errorf("scope %q", d.Scope)
	}
	return ban{prefix: p, expires: now.Add(dur)}, nil
}

// active drops expired entries and returns one entry per prefix, with its latest expiry.
// Prefixes in neverBlock, non-global addresses and overly wide ranges are left out.
// The result is ordered by expiry, latest first.
func (s *decisionSet) active(now time.Time, neverBlock []netip.Prefix) []ban {
	latest := map[netip.Prefix]time.Time{}
	for id, b := range s.byID {
		if !b.expires.After(now) {
			delete(s.byID, id)
			continue
		}
		if !blockable(b.prefix, neverBlock) {
			continue
		}
		if b.expires.After(latest[b.prefix]) {
			latest[b.prefix] = b.expires
		}
	}
	out := make([]ban, 0, len(latest))
	for p, e := range latest {
		out = append(out, ban{prefix: p, expires: e})
	}
	slices.SortFunc(out, func(a, b ban) int {
		if c := b.expires.Compare(a.expires); c != 0 {
			return c
		}
		return comparePrefix(a.prefix, b.prefix)
	})
	return out
}

func blockable(p netip.Prefix, neverBlock []netip.Prefix) bool {
	a := p.Addr()
	if a.IsLoopback() || a.IsPrivate() || a.IsUnspecified() || a.IsMulticast() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return false
	}
	if (a.Is4() && p.Bits() < minPrefixV4) || (a.Is6() && p.Bits() < minPrefixV6) {
		return false
	}
	for _, n := range neverBlock {
		if n.Overlaps(p) {
			return false
		}
	}
	return true
}

func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return cmp.Compare(a.Bits(), b.Bits())
}
