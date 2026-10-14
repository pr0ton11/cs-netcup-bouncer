package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pr0ton11/netcup-scp-go/scp"
)

// apiError is a failed SCP API call.
type apiError struct {
	op         string
	status     int
	retryAfter time.Duration
	body       string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("netcup %s: HTTP %d: %s", e.op, e.status, e.body)
}

func checkResponse(op string, resp *http.Response, body []byte, want ...int) error {
	if slices.Contains(want, resp.StatusCode) {
		return nil
	}
	b := strings.TrimSpace(string(body))
	if len(b) > 512 {
		b = b[:512] + "…"
	}
	return &apiError{op: op, status: resp.StatusCode, retryAfter: parseRetryAfter(resp.Header.Get("Retry-After")), body: b}
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}

// netcupFirewall manages one user policy and its assignment to one server interface.
type netcupFirewall struct {
	api      *scp.ClientWithResponses
	userID   int32
	serverID int32
	mac      string
}

// findPolicy returns the user policy with the given name, or nil if there is none.
func (n *netcupFirewall) findPolicy(ctx context.Context, name string) (*scp.FirewallPolicy, error) {
	resp, err := n.api.GetApiV1UsersUserIdFirewallPoliciesWithResponse(ctx, n.userID,
		&scp.GetApiV1UsersUserIdFirewallPoliciesParams{Q: &name, Limit: ptr[int32](100)})
	if err != nil {
		return nil, fmt.Errorf("netcup list policies: %w", err)
	}
	if err := checkResponse("list policies", resp.HTTPResponse, resp.Body, http.StatusOK); err != nil {
		return nil, err
	}
	var found *scp.FirewallPolicy
	for _, p := range *resp.JSON200 {
		if p.Name != nil && *p.Name == name && p.Id != nil {
			if found != nil {
				return nil, fmt.Errorf("netcup: more than one policy named %q", name)
			}
			found = &p
		}
	}
	if found == nil {
		return nil, nil
	}
	// The listing may leave out the rules; read the policy itself.
	return n.getPolicy(ctx, *found.Id)
}

func (n *netcupFirewall) getPolicy(ctx context.Context, id int32) (*scp.FirewallPolicy, error) {
	resp, err := n.api.GetApiV1UsersUserIdFirewallPoliciesIdWithResponse(ctx, n.userID, id)
	if err != nil {
		return nil, fmt.Errorf("netcup get policy: %w", err)
	}
	if err := checkResponse("get policy", resp.HTTPResponse, resp.Body, http.StatusOK); err != nil {
		return nil, err
	}
	return resp.JSON200, nil
}

func (n *netcupFirewall) createPolicy(ctx context.Context, save scp.FirewallPolicySave) (*scp.FirewallPolicy, error) {
	resp, err := n.api.PostApiV1UsersUserIdFirewallPoliciesWithResponse(ctx, n.userID, save)
	if err != nil {
		return nil, fmt.Errorf("netcup create policy: %w", err)
	}
	if err := checkResponse("create policy", resp.HTTPResponse, resp.Body, http.StatusCreated); err != nil {
		return nil, err
	}
	if resp.JSON201 == nil || resp.JSON201.Id == nil {
		return nil, errors.New("netcup create policy: no policy ID in response")
	}
	return resp.JSON201, nil
}

func (n *netcupFirewall) putPolicy(ctx context.Context, id int32, save scp.FirewallPolicySave) error {
	resp, err := n.api.PutApiV1UsersUserIdFirewallPoliciesIdWithResponse(ctx, n.userID, id, save)
	if err != nil {
		return fmt.Errorf("netcup update policy: %w", err)
	}
	return checkResponse("update policy", resp.HTTPResponse, resp.Body, http.StatusOK, http.StatusAccepted)
}

func (n *netcupFirewall) getFirewall(ctx context.Context) (*scp.ServerFirewall, error) {
	resp, err := n.api.GetApiV1ServersServerIdInterfacesMacFirewallWithResponse(ctx, n.serverID, n.mac, nil)
	if err != nil {
		return nil, fmt.Errorf("netcup get firewall: %w", err)
	}
	if err := checkResponse("get firewall", resp.HTTPResponse, resp.Body, http.StatusOK); err != nil {
		return nil, err
	}
	return resp.JSON200, nil
}

// ensureAssigned attaches the policy to the interface, ahead of the other user policies.
// The PUT replaces the whole assignment, so it sends the existing user and copied
// policies along. It reports whether it changed the assignment.
func (n *netcupFirewall) ensureAssigned(ctx context.Context, policyID int32) (bool, error) {
	fw, err := n.getFirewall(ctx)
	if err != nil {
		return false, err
	}
	save := scp.ServerFirewallSave{
		Active:         fw.Active,
		UserPolicies:   []scp.IdentifierInt{{Id: policyID}},
		CopiedPolicies: []scp.IdentifierInt{},
	}
	assigned := false
	for _, p := range deref(fw.UserPolicies) {
		if p.Id == nil {
			continue
		}
		if *p.Id == policyID {
			assigned = true
			continue
		}
		save.UserPolicies = append(save.UserPolicies, scp.IdentifierInt{Id: *p.Id})
	}
	if assigned {
		return false, nil
	}
	for _, p := range deref(fw.CopiedPolicies) {
		if p.Id != nil {
			save.CopiedPolicies = append(save.CopiedPolicies, scp.IdentifierInt{Id: *p.Id})
		}
	}
	resp, err := n.api.PutApiV1ServersServerIdInterfacesMacFirewallWithResponse(ctx, n.serverID, n.mac, save)
	if err != nil {
		return false, fmt.Errorf("netcup assign policy: %w", err)
	}
	if err := checkResponse("assign policy", resp.HTTPResponse, resp.Body, http.StatusOK, http.StatusAccepted); err != nil {
		return false, err
	}
	return true, nil
}

func deref[T any](s *[]T) []T {
	if s == nil {
		return nil
	}
	return *s
}
