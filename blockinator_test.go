package blockinator

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

const testKey = "test-blockinator-policy-key-12345678"

type recorder struct {
	dns.ResponseWriter
	msg     *dns.Msg
	address net.Addr
}

func (r *recorder) RemoteAddr() net.Addr      { return r.address }
func (r *recorder) WriteMsg(m *dns.Msg) error { r.msg = m.Copy(); return nil }

type nextHandler struct{ calls int }

func (n *nextHandler) Name() string { return "next" }
func (n *nextHandler) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	n.calls++
	m := new(dns.Msg)
	m.SetReply(r)
	return 0, w.WriteMsg(m)
}
func config(t *testing.T, endpoint, options string) *Blockinator {
	t.Helper()
	t.Setenv("BLOCKINATOR_TEST_KEY", testKey)
	b, err := parse(caddy.NewTestController("dns", "blockinator "+endpoint+" {\napi_key_env BLOCKINATOR_TEST_KEY\n"+options+"\n}"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.client.CloseIdleConnections)
	return b
}
func writer() *recorder {
	return &recorder{address: &net.UDPAddr{IP: net.ParseIP("192.0.2.4"), Port: 12345}}
}
func query(qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("blocked.example.", qtype)
	return m
}

func TestModesAndMetadata(t *testing.T) {
	for _, mode := range []string{"allow", "nxdomain", "refused", "nodata", "zero"} {
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT, 65400} {
			t.Run(fmt.Sprintf("%s-%d", mode, qtype), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/api/v1/decision" || r.Method != "POST" || r.Header.Get("X-API-Key") != testKey {
						t.Error("incorrect policy request")
					}
					var p policyRequest
					if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
						t.Error(err)
					}
					if p.Client.IP != "192.0.2.4" || p.Client.Port != 12345 || p.Protocol != "udp" || p.ServerID != "coredns-1" {
						t.Errorf("bad metadata: %+v", p)
					}
					if len(p.DNS.Questions) != 1 || p.DNS.Questions[0].Name != "blocked.example." {
						t.Error("bad questions")
					}
					fmt.Fprintf(w, `{"block":%t,"response_mode":%q}`, mode != "allow", mode)
				}))
				defer server.Close()
				b := config(t, server.URL+"/api/v1/decision", "")
				next := new(nextHandler)
				b.Next = next
				w := writer()
				m := query(qtype)
				m.SetEdns0(1232, true)
				m.AuthenticatedData = true
				if _, err := b.ServeDNS(context.Background(), w, m); err != nil {
					t.Fatal(err)
				}
				if mode == "allow" {
					if next.calls != 1 {
						t.Fatal("did not call next")
					}
					return
				}
				if next.calls != 0 || w.msg == nil {
					t.Fatal("blocked query reached next")
				}
				expected := map[string]int{"nxdomain": 3, "refused": 5, "nodata": 0, "zero": 0}[mode]
				if w.msg.Rcode != expected || w.msg.AuthenticatedData {
					t.Fatalf("bad response: %v", w.msg)
				}
				if mode == "zero" && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
					if len(w.msg.Answer) != 1 || w.msg.Answer[0].Header().Ttl != 0 {
						t.Fatal("missing zero answer")
					}
				} else if len(w.msg.Answer) != 0 {
					t.Fatal("unexpected answers")
				}
			})
		}
	}
}

func TestFailures(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"block":"false"}`, `{"block":true,"response_mode":"bad"}`, `{"block":true,"response_mode":[]}`, strings.Repeat("x", 17000), `{"block":false} trailing`} {
		for _, mode := range []string{"open", "closed"} {
			t.Run(mode+body[:min(10, len(body))], func(t *testing.T) {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
				defer s.Close()
				b := config(t, s.URL+"/api/v1/decision", "fail_mode "+mode)
				n := new(nextHandler)
				b.Next = n
				w := writer()
				b.ServeDNS(context.Background(), w, query(dns.TypeA))
				if mode == "open" && n.calls != 1 {
					t.Fatal("fail-open failed")
				}
				if mode == "closed" && (n.calls != 0 || w.msg.Rcode != dns.RcodeServerFailure) {
					t.Fatal("fail-closed failed")
				}
			})
		}
	}
}

func TestHTTPAndTimeout(t *testing.T) {
	for _, status := range []int{401, 500, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "http://127.0.0.1:1/leak")
				w.WriteHeader(status)
			}))
			defer s.Close()
			b := config(t, s.URL+"/api/v1/decision", "")
			if _, err := b.lookup(context.Background(), writer(), query(dns.TypeA)); err == nil {
				t.Fatal("accepted HTTP failure")
			}
		})
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(w, `{"block":false}`)
	}))
	defer s.Close()
	b := config(t, s.URL+"/api/v1/decision", "timeout 10ms")
	if _, err := b.lookup(context.Background(), writer(), query(dns.TypeA)); err == nil {
		t.Fatal("missing timeout")
	}
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"block":false}`) }))
	defer tls.Close()
	b = config(t, tls.URL+"/api/v1/decision", "")
	if _, err := b.lookup(context.Background(), writer(), query(dns.TypeA)); err == nil {
		t.Fatal("trusted unknown certificate")
	}
}

func TestConcurrencyAndCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-release
		fmt.Fprint(w, `{"block":false}`)
	}))
	defer s.Close()
	defer close(release)
	b := config(t, s.URL+"/api/v1/decision", "max_concurrent 1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := b.lookup(ctx, writer(), query(dns.TypeA)); done <- err }()
	<-started
	if _, err := b.lookup(context.Background(), writer(), query(dns.TypeA)); err == nil {
		t.Fatal("limit ignored")
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancellation ignored")
	}
	if len(b.slots) != 0 {
		t.Fatal("slot leaked")
	}
}

func TestIPv6TCPAndMalformed(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p policyRequest
		json.NewDecoder(r.Body).Decode(&p)
		if p.Client.IP != "2001:db8::4" || p.Protocol != "tcp" {
			t.Error("lost IPv6/TCP metadata")
		}
		fmt.Fprint(w, `{"block":false}`)
	}))
	defer s.Close()
	b := config(t, s.URL+"/api/v1/decision", "")
	b.Next = new(nextHandler)
	w := &recorder{address: &net.TCPAddr{IP: net.ParseIP("2001:db8::4"), Port: 1234}}
	b.ServeDNS(context.Background(), w, query(dns.TypeA))
	for _, m := range []*dns.Msg{new(dns.Msg), {Question: []dns.Question{{Name: "a.", Qtype: 1, Qclass: 1}, {Name: "b.", Qtype: 1, Qclass: 1}}}} {
		w = writer()
		b.ServeDNS(context.Background(), w, m)
		if w.msg.Rcode != dns.RcodeFormatError {
			t.Fatal("malformed packet accepted")
		}
	}
}

func TestConfiguration(t *testing.T) {
	t.Setenv("KEY", testKey)
	for _, input := range []string{
		"blockinator http://example.com/api/v1/decision",
		"blockinator http://user:password@example.com/api/v1/decision {\napi_key_env KEY\n}",
		"blockinator http://example.com/wrong {\napi_key_env KEY\n}",
		"blockinator http://example.com/api/v1/decision {\napi_key_env KEY\ntimeout 0\n}",
		"blockinator http://example.com/api/v1/decision {\napi_key_env KEY\nmax_concurrent -1\n}",
		"blockinator http://example.com/api/v1/decision {\napi_key_env KEY\nfail_mode bogus\n}",
		"blockinator http://example.com/api/v1/decision {\napi_key_env KEY\nunknown x\n}",
		"blockinator http://example.com/api/v1/decision {\napi_key_env KEY\napi_key_env KEY\n}",
	} {
		if _, err := parse(caddy.NewTestController("dns", input)); err == nil {
			t.Errorf("accepted invalid config: %s", input)
		}
	}
	if err := setup(caddy.NewTestController("dns", "blockinator http://localhost:8080/api/v1/decision {\napi_key_env KEY\n}")); err != nil {
		t.Fatal(err)
	}
	var _ plugin.Handler = (*Blockinator)(nil)
}
