// Package loki is a minimal Loki HTTP query client. We only need
// query_range and instant query; no dependencies, no auth, no streaming.
package loki

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Sample is one log line returned by Loki.
type Sample struct {
	Time   time.Time
	Line   string
	Labels map[string]string
}

// QueryRange runs a LogQL query over [start, end] and returns up to `limit`
// samples. Loki's API spreads results across multiple "streams," each with
// its own label set; we flatten into a single Sample slice in chronological
// order so downstream code doesn't have to think about streams.
func (c *Client) QueryRange(ctx context.Context, q string, start, end time.Time, limit int) ([]Sample, error) {
	if limit <= 0 {
		limit = 1000
	}
	u, err := url.Parse(c.BaseURL + "/loki/api/v1/query_range")
	if err != nil {
		return nil, err
	}
	v := url.Values{}
	v.Set("query", q)
	v.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	v.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	v.Set("limit", strconv.Itoa(limit))
	v.Set("direction", "FORWARD")
	u.RawQuery = v.Encode()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("loki %d", resp.StatusCode)
	}

	var raw struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Stream map[string]string `json:"stream"`
				// Each value is [unix_nano_string, line]
				Values [][]string `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	var out []Sample
	for _, r := range raw.Data.Result {
		for _, v := range r.Values {
			if len(v) != 2 {
				continue
			}
			ns, _ := strconv.ParseInt(v[0], 10, 64)
			out = append(out, Sample{
				Time:   time.Unix(0, ns),
				Line:   v[1],
				Labels: r.Stream,
			})
		}
	}
	return out, nil
}
