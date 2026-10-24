package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func inboundFixture(id, listen string) InboundSpec {
	return InboundSpec{ID: id, Name: id, Enabled: true, Listen: listen, SNI: "www.example.com", Transports: []string{"tcp", "xhttp", "quic"}, XHTTPPath: "/sync", WireVersion: 7}
}

func TestInboundSettingsBelongToListenerNotClient(t *testing.T) {
	first := inboundFixture("first", "127.0.0.1:1026")
	second := inboundFixture("second", "127.0.0.1:1027")
	second.SNI = "other.example.com"
	if err := validateInboundSet([]InboundSpec{first, second}); err != nil {
		t.Fatal(err)
	}
	refs := []SubscriptionInboundRef{{ServerID: "vds", InboundID: first.ID}, {ServerID: "vds", InboundID: second.ID}}
	servers := map[string]map[string]InboundSpec{"vds": {first.ID: first, second.ID: second}}
	resolved, err := resolveInboundRefs(refs, servers)
	if err != nil || len(resolved) != 2 || resolved[0].Spec.SNI == resolved[1].Spec.SNI {
		t.Fatalf("independent inbound settings were lost: %v", err)
	}
	first.SNI = "updated.example.com"
	servers["vds"][first.ID] = first
	resolved, err = resolveInboundRefs(refs, servers)
	if err != nil || resolved[0].Spec.SNI != first.SNI {
		t.Fatal("subscription retained a stale copy of inbound settings")
	}
	resolved[0].Spec.Transports[0] = "changed"
	if servers["vds"][first.ID].Transports[0] != "tcp" {
		t.Fatal("subscription mutated server-owned transports")
	}
	data, _ := json.Marshal(refs)
	if strings.Contains(string(data), "sni") || strings.Contains(string(data), "transports") {
		t.Fatal("client references contain server-owned settings")
	}
}

func TestInboundReferencesRejectMissingOrDuplicateBindings(t *testing.T) {
	first := inboundFixture("first", "127.0.0.1:1026")
	servers := map[string]map[string]InboundSpec{"vds": {first.ID: first}}
	for _, refs := range [][]SubscriptionInboundRef{
		{{ServerID: "vds", InboundID: "missing"}},
		{{ServerID: "missing", InboundID: first.ID}},
		{{ServerID: "vds", InboundID: first.ID}, {ServerID: "vds", InboundID: first.ID}},
	} {
		if _, err := resolveInboundRefs(refs, servers); err == nil {
			t.Fatal("invalid binding accepted")
		}
	}
}

func TestInboundPortConflictsAndTransportSharing(t *testing.T) {
	first := inboundFixture("first", ":1026")
	second := inboundFixture("second", "127.0.0.1:1026")
	if validateInboundSet([]InboundSpec{first, second}) == nil {
		t.Fatal("overlapping wildcard listener accepted")
	}
	first.Transports = []string{"quic"}
	second.Transports = []string{"tcp", "xhttp"}
	if err := validateInboundSet([]InboundSpec{first, second}); err != nil {
		t.Fatal(err)
	}
	first.Transports = []string{"tcp"}
	second.Enabled = false
	if err := validateInboundSet([]InboundSpec{first, second}); err != nil {
		t.Fatal(err)
	}
}

func TestInboundSpecRejectsAmbiguousOrLegacySettings(t *testing.T) {
	for _, change := range []func(*InboundSpec){
		func(s *InboundSpec) { s.WireVersion = 4 },
		func(s *InboundSpec) { s.Transports = []string{"tcp", "tcp"} },
		func(s *InboundSpec) { s.SNI = "bad.example\r\n" },
		func(s *InboundSpec) { s.Listen = "host.example:1026" },
		func(s *InboundSpec) { s.Listen = "127.0.0.1:0" },
		func(s *InboundSpec) { s.XHTTPPath = "/sync?secret=1" },
		func(s *InboundSpec) { s.Quic.SocketBufferSizeMB = -1 },
		func(s *InboundSpec) { s.Quic.SocketBufferSizeMB = 65 },
		func(s *InboundSpec) { s.Quic.MaxIdleTimeoutSec = 86401 },
		func(s *InboundSpec) { s.Quic.MaxIdleTimeoutSec = 5 },
		func(s *InboundSpec) { s.Quic.StreamReceiveWindowMB = 5; s.Quic.ConnReceiveWindowMB = 4 },
		func(s *InboundSpec) { s.Yamux.MaxStreamWindowKB = 255 },
		func(s *InboundSpec) { s.Yamux.MaxStreamWindowKB = 1 << 30 },
		func(s *InboundSpec) { s.Yamux.WriteTimeoutSec = -1 },
	} {
		spec := inboundFixture("first", "127.0.0.1:1026")
		change(&spec)
		if spec.validate() == nil {
			t.Fatal("invalid inbound accepted")
		}
	}
}
