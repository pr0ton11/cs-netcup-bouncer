package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// lapiDecision is a decision as the CrowdSec LAPI returns it from /v1/decisions/stream.
type lapiDecision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

type streamResponse struct {
	New     []lapiDecision `json:"new"`
	Deleted []lapiDecision `json:"deleted"`
}

// lapiClient pulls decisions from the CrowdSec local API.
type lapiClient struct {
	baseURL string
	apiKey  string
	origins []string // if set, only decisions from these origins
	http    *http.Client
}

// stream returns the decisions added and deleted since the last pull. With startup set, New
// holds every active decision instead.
func (c *lapiClient) stream(ctx context.Context, startup bool) (*streamResponse, error) {
	q := url.Values{
		"startup": {fmt.Sprint(startup)},
		"scopes":  {"ip,range"},
	}
	if len(c.origins) > 0 {
		q.Set("origins", strings.Join(c.origins, ","))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.baseURL, "/")+"/v1/decisions/stream?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("User-Agent", "crowdsec-netcup-bouncer/"+version)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lapi: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("lapi: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var sr streamResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("lapi: decode stream: %w", err)
	}
	return &sr, nil
}
