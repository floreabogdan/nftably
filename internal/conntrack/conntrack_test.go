package conntrack

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	sample := `ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.5 dst=10.0.0.1 sport=51000 dport=22 src=10.0.0.1 dst=10.0.0.5 sport=22 dport=51000 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 29 src=10.0.0.5 dst=1.1.1.1 sport=40000 dport=53 src=1.1.1.1 dst=10.0.0.5 sport=53 dport=40000 mark=0 use=1
ipv4     2 tcp      6 118 SYN_SENT src=203.0.113.9 dst=10.0.0.1 sport=55555 dport=23 [UNREPLIED] src=10.0.0.1 dst=203.0.113.9 sport=23 dport=55555 mark=0 use=1
ipv6     10 tcp     6 431999 ESTABLISHED src=2001:db8::5 dst=2001:db8::1 sport=51001 dport=443 src=2001:db8::1 dst=2001:db8::5 sport=443 dport=51001 [ASSURED] use=1
ipv4     2 icmp     1 29 src=10.0.0.5 dst=10.0.0.1 type=8 code=0 id=6 src=10.0.0.1 dst=10.0.0.5 type=0 code=0 id=6 mark=0 use=1
garbage line
`
	flows := parse(strings.NewReader(sample))
	if len(flows) != 5 {
		t.Fatalf("flows: %d %+v", len(flows), flows)
	}

	tcp := flows[0]
	if tcp.Proto != "tcp" || tcp.State != "ESTABLISHED" || !tcp.Assured ||
		tcp.Src.String() != "10.0.0.5" || tcp.Dst.String() != "10.0.0.1" ||
		tcp.SPort != 51000 || tcp.DPort != 22 {
		t.Fatalf("tcp flow: %+v", tcp)
	}
	// The reply-direction src/dst/ports must not overwrite the original.
	if tcp.Dst.String() == "10.0.0.5" || tcp.DPort == 51000 {
		t.Fatalf("reply direction leaked: %+v", tcp)
	}

	udp := flows[1]
	if udp.Proto != "udp" || udp.State != "" || udp.DPort != 53 {
		t.Fatalf("udp flow: %+v", udp)
	}

	syn := flows[2]
	if syn.State != "SYN_SENT" || syn.Assured {
		t.Fatalf("syn flow: %+v", syn)
	}

	v6 := flows[3]
	if !v6.Src.Is6() || v6.DPort != 443 {
		t.Fatalf("v6 flow: %+v", v6)
	}

	icmp := flows[4]
	if icmp.Proto != "icmp" || icmp.SPort != 0 || icmp.State != "" {
		t.Fatalf("icmp flow: %+v", icmp)
	}
}

func TestParseConntrackToolDialect(t *testing.T) {
	// conntrack -L output has no leading l3 columns.
	sample := `tcp      6 431999 ESTABLISHED src=192.0.2.2 dst=192.0.2.1 sport=41000 dport=8080 src=10.99.0.2 dst=192.0.2.2 sport=80 dport=41000 [ASSURED] mark=0 use=1
udp      17 29 src=10.0.0.5 dst=1.1.1.1 sport=40000 dport=53 [UNREPLIED] src=1.1.1.1 dst=10.0.0.5 sport=53 dport=40000 mark=0 use=1
`
	flows := parse(strings.NewReader(sample))
	if len(flows) != 2 {
		t.Fatalf("flows: %+v", flows)
	}
	if flows[0].Proto != "tcp" || flows[0].State != "ESTABLISHED" || flows[0].DPort != 8080 ||
		flows[0].Src.String() != "192.0.2.2" {
		t.Fatalf("tool tcp flow: %+v", flows[0])
	}
	if flows[1].Proto != "udp" || flows[1].State != "UNREPLIED" || flows[1].DPort != 53 {
		t.Fatalf("tool udp flow: %+v", flows[1])
	}
}
