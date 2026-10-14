// Command crowdsec-netcup-bouncer blocks the addresses CrowdSec bans in the netcup
// firewall, so that their traffic never reaches the server.
//
// It pulls decisions from the CrowdSec local API and keeps one netcup firewall policy in
// line with them: DROP rules for the banned addresses, followed by ACCEPT rules. Addresses
// are only kept in memory and on netcup's firewall, for as long as the ban lasts.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pr0ton11/netcup-scp-go/auth"
	"github.com/pr0ton11/netcup-scp-go/scp"
	"golang.org/x/oauth2"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println(version)
		return
	}
	log, err := newLogger()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var errs []error
	check := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	cfg := bouncerConfig{
		policyName:  env("NETCUP_POLICY_NAME", "crowdsec-bouncer"),
		dryRun:      envBool("DRY_RUN", false),
		acceptOnly:  envBool("ACCEPT_ONLY", false),
		clearOnExit: envBool("CLEAR_ON_EXIT", true),
	}
	var err error
	cfg.pollInterval, err = envDuration("POLL_INTERVAL", 30*time.Second)
	check(err)
	cfg.syncInterval, err = envDuration("SYNC_INTERVAL", 2*time.Minute)
	check(err)
	cfg.driftCheck, err = envDuration("DRIFT_CHECK_INTERVAL", time.Hour)
	check(err)
	cfg.policy.maxRules, err = envInt("NETCUP_MAX_RULES", 400)
	check(err)
	cfg.policy.neverBlock, err = envPrefixes("NEVER_BLOCK")
	check(err)
	cfg.policy.dropProtocols, err = envProtocols("NETCUP_DROP_PROTOCOLS", "TCP,UDP")
	check(err)
	if os.Getenv("NETCUP_ACCEPT_RULES_FILE") != "" {
		check(errors.New("NETCUP_ACCEPT_RULES_FILE was removed in v0.1.1: the bouncer only adds DROP rules now; put your own ACCEPT rules in a policy of your own"))
	}

	apiKey := os.Getenv("CROWDSEC_LAPI_KEY")
	if apiKey == "" {
		apiKey, err = readSecret(env("CROWDSEC_LAPI_KEY_FILE", "/run/secrets/netcup-bouncer-lapi-key"))
		check(err)
	}
	httpClient := &http.Client{Timeout: 30 * time.Second}
	lapi := &lapiClient{
		baseURL: env("CROWDSEC_LAPI_URL", "http://127.0.0.1:8080"),
		apiKey:  apiKey,
		origins: envList("CROWDSEC_ORIGINS"),
		http:    httpClient,
	}

	var fw *netcupFirewall
	if !cfg.dryRun {
		fw = &netcupFirewall{mac: strings.ToLower(os.Getenv("NETCUP_INTERFACE_MAC"))}
		fw.userID, err = envInt32("NETCUP_USER_ID")
		check(err)
		fw.serverID, err = envInt32("NETCUP_SERVER_ID")
		check(err)
		if fw.mac == "" {
			check(errors.New("NETCUP_INTERFACE_MAC is required"))
		}
		token, err := auth.ReadRefreshToken(env("NETCUP_REFRESH_TOKEN_FILE", "/run/secrets/netcup-refresh-token"))
		check(err)
		if len(errs) == 0 {
			// The refresh token stays valid when netcup rotates it, so the secret is never
			// written back.
			octx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
			client := oauth2.NewClient(octx, auth.NewTokenSource(octx, token, nil))
			client.Timeout = 30 * time.Second
			fw.api, err = scp.NewClientWithResponses(env("NETCUP_API_URL", auth.Server), scp.WithHTTPClient(client))
			check(err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if n := cfg.policy.maxBlocked(); n == 0 {
		return fmt.Errorf("NETCUP_MAX_RULES=%d leaves no room for one address per drop protocol", cfg.policy.maxRules)
	}

	log.Info("starting", "version", version, "dry_run", cfg.dryRun, "accept_only", cfg.acceptOnly,
		"policy", cfg.policyName, "fallback_policy", cfg.fallbackName(), "drop_protocols", fmt.Sprint(cfg.policy.dropProtocols),
		"max_blocked", cfg.policy.maxBlocked(), "never_block", len(cfg.policy.neverBlock),
		"origins", originsLabel(lapi.origins))
	return newBouncer(cfg, lapi, fw, log).run(ctx)
}

// newLogger returns a logger in LOG_FORMAT: json (the default) or text.
func newLogger() (*slog.Logger, error) {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if envBool("DEBUG", false) {
		opts.Level = slog.LevelDebug
	}
	switch f := env("LOG_FORMAT", "json"); f {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), nil
	default:
		return nil, fmt.Errorf("LOG_FORMAT: want json or text, got %q", f)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	b, err := strconv.ParseBool(os.Getenv(key))
	if err != nil {
		return def
	}
	return b
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: want a positive duration like 30s, got %q", key, v)
	}
	return d, nil
}

func envInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: want a positive number, got %q", key, v)
	}
	return n, nil
}

func envInt32(key string) (int32, error) {
	v := os.Getenv(key)
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s is required and must be a number, got %q", key, v)
	}
	return int32(n), nil
}

func envPrefixes(key string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range strings.FieldsFunc(os.Getenv(key), isListSep) {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, fmt.Errorf("%s: %q is not an address or prefix", key, s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func envProtocols(key, def string) ([]scp.FirewallProtocol, error) {
	var out []scp.FirewallProtocol
	for _, s := range strings.FieldsFunc(env(key, def), isListSep) {
		p := scp.FirewallProtocol(strings.ToUpper(s))
		if p == "ICMPV6" {
			p = scp.ICMPv6
		}
		if !p.Valid() {
			return nil, fmt.Errorf("%s: unknown protocol %q", key, s)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no protocols", key)
	}
	return out, nil
}

// envList returns the comma-separated values of key, without duplicates, in order.
func envList(key string) []string {
	var out []string
	for _, v := range strings.FieldsFunc(os.Getenv(key), isListSep) {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func originsLabel(origins []string) string {
	if len(origins) == 0 {
		return "all"
	}
	return strings.Join(origins, ",")
}

func isListSep(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }

func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return s, nil
}
