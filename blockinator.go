// Package blockinator implements CoreDNS policy enforcement using Blockinator.
package blockinator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
)

var logger = log.NewWithPlugin("blockinator")

// Blockinator checks policy before passing allowed queries to the next plugin.
type Blockinator struct {
	Next                       plugin.Handler
	endpoint, apiKey, serverID string
	failClosed                 bool
	client                     *http.Client
	slots                      chan struct{}
	lastWarning                atomic.Int64
}

func (b *Blockinator) Name() string { return "blockinator" }

type question struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}
type policyRequest struct {
	ServerID string `json:"server_id"`
	Protocol string `json:"protocol"`
	Client   struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"client"`
	DNS struct {
		Questions []question `json:"questions"`
	} `json:"dns"`
}
type decision struct {
	Block *bool  `json:"block"`
	Mode  string `json:"response_mode"`
}

func (b *Blockinator) lookup(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (decision, error) {
	select {
	case b.slots <- struct{}{}:
		defer func() { <-b.slots }()
	default:
		return decision{}, fmt.Errorf("policy concurrency limit reached")
	}
	host, portText, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil || net.ParseIP(host) == nil {
		return decision{}, fmt.Errorf("invalid client address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return decision{}, fmt.Errorf("invalid client port")
	}
	payload := policyRequest{ServerID: b.serverID, Protocol: w.RemoteAddr().Network()}
	payload.Client.IP, payload.Client.Port = host, port
	for _, q := range r.Question {
		qt := dns.TypeToString[q.Qtype]
		if qt == "" {
			qt = fmt.Sprintf("TYPE%d", q.Qtype)
		}
		qc := dns.ClassToString[q.Qclass]
		if qc == "" {
			qc = fmt.Sprintf("CLASS%d", q.Qclass)
		}
		payload.DNS.Questions = append(payload.DNS.Questions, question{q.Name, qt, qc})
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return decision{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, bytes.NewReader(body))
	if err != nil {
		return decision{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", b.apiKey)
	resp, err := b.client.Do(req)
	if err != nil {
		return decision{}, fmt.Errorf("policy transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decision{}, fmt.Errorf("policy HTTP status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16385))
	if err != nil || len(data) > 16384 {
		return decision{}, fmt.Errorf("invalid policy response size")
	}
	var d decision
	if err = json.Unmarshal(data, &d); err != nil || d.Block == nil {
		return decision{}, fmt.Errorf("invalid policy decision")
	}
	if *d.Block {
		switch d.Mode {
		case "nxdomain", "refused", "nodata", "zero":
		default:
			return decision{}, fmt.Errorf("invalid policy response mode")
		}
	}
	return d, nil
}

func (b *Blockinator) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if r.Response || r.Opcode != dns.OpcodeQuery || len(r.Question) != 1 {
		// DNS packets with multiple questions have ambiguous cache/response semantics.
		return reply(w, r, dns.RcodeFormatError, "")
	}
	d, err := b.lookup(ctx, w, r)
	if err != nil {
		// Avoid flooding logs during outages; never log credentials or query names.
		now := time.Now().Unix()
		previous := b.lastWarning.Load()
		if now-previous >= 60 && b.lastWarning.CompareAndSwap(previous, now) {
			logger.Warning("Policy check unavailable; applying configured fail_mode")
		}
		if b.failClosed {
			return reply(w, r, dns.RcodeServerFailure, "")
		}
		return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
	}
	if !*d.Block {
		return plugin.NextOrFailure(b.Name(), b.Next, ctx, w, r)
	}
	switch d.Mode {
	case "nxdomain":
		return reply(w, r, dns.RcodeNameError, "")
	case "refused":
		return reply(w, r, dns.RcodeRefused, "")
	default:
		return reply(w, r, dns.RcodeSuccess, d.Mode)
	}
}

func reply(w dns.ResponseWriter, r *dns.Msg, rcode int, mode string) (int, error) {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	m.RecursionAvailable = true
	m.AuthenticatedData = false
	if mode == "zero" && len(r.Question) == 1 && r.Question[0].Qclass == dns.ClassINET {
		q := r.Question[0]
		header := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: q.Qclass, Ttl: 0}
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = []dns.RR{&dns.A{Hdr: header, A: net.IPv4zero}}
		case dns.TypeAAAA:
			m.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.IPv6zero}}
		}
	}
	if opt := r.IsEdns0(); opt != nil {
		m.SetEdns0(opt.UDPSize(), false)
	}
	return dns.RcodeSuccess, w.WriteMsg(m)
}
