package blockinator

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("blockinator", setup) }

func setup(c *caddy.Controller) error {
	b, err := parse(c)
	if err != nil {
		return plugin.Error("blockinator", err)
	}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		b.Next = next
		return b
	})
	c.OnShutdown(func() error { b.client.CloseIdleConnections(); return nil })
	return nil
}

func parse(c *caddy.Controller) (*Blockinator, error) {
	b := &Blockinator{serverID: "coredns-1"}
	timeout, limit := 250*time.Millisecond, 128
	seen := make(map[string]bool)
	count := 0
	for c.Next() {
		count++
		if count > 1 {
			return nil, fmt.Errorf("only one blockinator directive is allowed per server block")
		}
		args := c.RemainingArgs()
		if len(args) != 1 {
			return nil, c.ArgErr()
		}
		b.endpoint = args[0]
		for c.NextBlock() {
			name := c.Val()
			args := c.RemainingArgs()
			if len(args) != 1 {
				return nil, c.ArgErr()
			}
			if seen[name] {
				return nil, fmt.Errorf("duplicate blockinator option")
			}
			seen[name] = true
			value := args[0]
			switch name {
			case "api_key_env":
				b.apiKey = os.Getenv(value)
			case "server_id":
				b.serverID = value
			case "fail_mode":
				if value != "open" && value != "closed" {
					return nil, fmt.Errorf("fail_mode must be open or closed")
				}
				b.failClosed = value == "closed"
			case "timeout":
				d, err := time.ParseDuration(value)
				if err != nil || d <= 0 || d > 10*time.Second {
					return nil, fmt.Errorf("timeout must be greater than zero and at most 10s")
				}
				timeout = d
			case "max_concurrent":
				n, err := strconv.Atoi(value)
				if err != nil || n < 1 || n > 4096 {
					return nil, fmt.Errorf("max_concurrent must be 1 to 4096")
				}
				limit = n
			default:
				return nil, fmt.Errorf("unknown blockinator option")
			}
		}
	}
	u, err := url.Parse(b.endpoint)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Path != "/api/v1/decision" {
		return nil, fmt.Errorf("endpoint must be an http(s) URL ending in /api/v1/decision without credentials, query, or fragment")
	}
	if len(b.apiKey) < 24 || strings.IndexFunc(b.apiKey, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return nil, fmt.Errorf("api_key_env must name an environment variable containing a policy key of at least 24 printable characters")
	}
	if len(b.serverID) == 0 || len(b.serverID) > 255 {
		return nil, fmt.Errorf("server_id must contain 1 to 255 bytes")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxConnsPerHost = limit
	transport.MaxIdleConnsPerHost = limit
	transport.MaxIdleConns = limit
	transport.DisableCompression = true
	b.client = &http.Client{Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	b.slots = make(chan struct{}, limit)
	return b, nil
}
