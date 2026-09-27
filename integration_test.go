package blockinator

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestCoreDNSBinary verifies actual plugin registration/order and cache isolation.
// Set COREDNS_BINARY to the output of tools/build.sh to enable it.
func TestCoreDNSBinary(t *testing.T) {
	binary := os.Getenv("COREDNS_BINARY")
	if binary == "" {
		t.Skip("set COREDNS_BINARY to run live CoreDNS integration")
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	var policyCalls, upstreamCalls atomic.Int64
	var policyMode atomic.Value
	policyMode.Store("client")
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policyCalls.Add(1)
		var p policyRequest
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		mode := policyMode.Load().(string)
		if mode == "error" {
			w.WriteHeader(503)
			return
		}
		if mode == "client" {
			mode = "allow"
			if p.Client.IP == "127.0.0.2" {
				mode = "nxdomain"
			}
		}
		fmt.Fprintf(w, `{"block":%t,"response_mode":%q}`, mode != "allow", mode)
	}))
	defer api.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		upstreamCalls.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		rr, _ := dns.NewRR(r.Question[0].Name + " 300 IN A 192.0.2.123")
		m.Answer = []dns.RR{rr}
		w.WriteMsg(m)
	})}
	go upstream.ActivateAndServe()
	defer upstream.Shutdown()
	for _, failMode := range []string{"open", "closed"} {
		t.Run(failMode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			listener.Close()
			dir := t.TempDir()
			corefile := filepath.Join(dir, "Corefile")
			conf := fmt.Sprintf(`.:%d {
 bind 127.0.0.1
 errors
 blockinator %s/api/v1/decision {
  api_key_env POLICY_API_KEY
  fail_mode %s
 }
 cache 30
 forward . %s
}
`, port, api.URL, failMode, pc.LocalAddr())
			if err := os.WriteFile(corefile, []byte(conf), 0600); err != nil {
				t.Fatal(err)
			}
			logfile, err := os.Create(filepath.Join(dir, "coredns.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer logfile.Close()
			cmd := exec.Command(binary, "-conf", corefile)
			cmd.Env = append(os.Environ(), "POLICY_API_KEY="+testKey)
			cmd.Stdout = logfile
			cmd.Stderr = logfile
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			exchange := func(protocol, source string, qtype uint16) (*dns.Msg, error) {
				client := &dns.Client{Net: protocol, Timeout: 500 * time.Millisecond}
				addr := net.ParseIP(source)
				if protocol == "tcp" {
					client.Dialer = &net.Dialer{LocalAddr: &net.TCPAddr{IP: addr}}
				} else {
					client.Dialer = &net.Dialer{LocalAddr: &net.UDPAddr{IP: addr}}
				}
				m := query(qtype)
				result, _, err := client.Exchange(m, fmt.Sprintf("127.0.0.1:%d", port))
				return result, err
			}
			policyMode.Store("client")
			ready := false
			for i := 0; i < 50; i++ {
				if _, err := exchange("udp", "127.0.0.1", dns.TypeA); err == nil {
					ready = true
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if !ready {
				data, _ := os.ReadFile(logfile.Name())
				t.Fatalf("CoreDNS did not start: %s", data)
			}
			before := upstreamCalls.Load()
			policies := policyCalls.Load()
			// Repeated same-name requests must check policy even when allowed DNS is cached.
			for _, protocol := range []string{"udp", "tcp"} {
				for _, source := range []string{"127.0.0.1", "127.0.0.2", "127.0.0.1"} {
					m, err := exchange(protocol, source, dns.TypeA)
					if err != nil {
						t.Fatal(err)
					}
					if source == "127.0.0.2" {
						if m.Rcode != dns.RcodeNameError || len(m.Answer) != 0 {
							t.Fatal("client policy bypassed via cache")
						}
					} else if len(m.Answer) != 1 {
						t.Fatal("allowed client received blocked response")
					}
				}
			}
			if policyCalls.Load()-policies != 6 {
				t.Fatal("not every query reached policy API")
			}
			if upstreamCalls.Load() != before {
				t.Fatal("allowed queries did not use DNS cache")
			}
			for _, mode := range []string{"refused", "nodata", "zero"} {
				policyMode.Store(mode)
				m, err := exchange("tcp", "127.0.0.1", dns.TypeAAAA)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "refused" && m.Rcode != dns.RcodeRefused {
					t.Fatal("expected REFUSED")
				}
				if mode == "nodata" && (m.Rcode != 0 || len(m.Answer) != 0) {
					t.Fatal("expected NODATA")
				}
				if mode == "zero" && (len(m.Answer) != 1 || !strings.Contains(m.Answer[0].String(), "::")) {
					t.Fatal("expected zero IPv6")
				}
			}
			policyMode.Store("error")
			m, err := exchange("udp", "127.0.0.1", dns.TypeA)
			if err != nil {
				t.Fatal(err)
			}
			if failMode == "closed" && m.Rcode != dns.RcodeServerFailure {
				t.Fatal("fail-closed failed")
			}
			if failMode == "open" && len(m.Answer) != 1 {
				t.Fatal("fail-open failed")
			}
		})
	}
}
