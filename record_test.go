package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"syscall"
	"testing"

	"github.com/zinrai/socketrail/bpf"
)

func key(proto, dir uint8, local, remote string, lport, rport uint16) bpf.SocketrailFlowKey {
	k := bpf.SocketrailFlowKey{Proto: proto, Dir: dir, Lport: lport, Rport: rport}
	l, r := netip.MustParseAddr(local), netip.MustParseAddr(remote)
	if l.Is4() {
		k.Family = syscall.AF_INET
		a, b := l.As4(), r.As4()
		copy(k.Laddr[:], a[:])
		copy(k.Raddr[:], b[:])
	} else {
		k.Family = syscall.AF_INET6
		k.Laddr, k.Raddr = l.As16(), r.As16()
	}
	return k
}

func encode(t *testing.T, v any) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(buf.String())
}

func TestAnOutboundConnectionKeepsOnlyTheRemotePort(t *testing.T) {
	k := key(syscall.IPPROTO_TCP, dirOut, "192.0.2.2", "198.51.100.7", 0, 443)

	got := encode(t, render("T", k, bpf.SocketrailFlowVal{TxBytes: 10, RxBytes: 20, Conns: 3}))

	want := `{"timestamp":"T","proto":"tcp","dir":"out","family":"inet","remote":"198.51.100.7","remote_port":443,"local":"192.0.2.2","conns":3,"tx_bytes":10,"rx_bytes":20}`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestAnInboundConnectionKeepsOnlyTheLocalPort(t *testing.T) {
	k := key(syscall.IPPROTO_TCP, dirIn, "192.0.2.2", "198.51.100.7", 22, 0)

	got := encode(t, render("T", k, bpf.SocketrailFlowVal{RxBytes: 5, Conns: 1}))

	want := `{"timestamp":"T","proto":"tcp","dir":"in","family":"inet","remote":"198.51.100.7","local":"192.0.2.2","local_port":22,"conns":1,"tx_bytes":0,"rx_bytes":5}`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestTCPWithNoNewConnectionsSaysZero(t *testing.T) {
	k := key(syscall.IPPROTO_TCP, dirOut, "192.0.2.2", "198.51.100.7", 0, 443)

	got := encode(t, render("T", k, bpf.SocketrailFlowVal{TxBytes: 19}))

	if !strings.Contains(got, `"conns":0`) {
		t.Errorf("a long-lived connection lost its conns field: %s", got)
	}
}

func TestUDPHasNoDirectionAndNoConnectionCount(t *testing.T) {
	k := key(syscall.IPPROTO_UDP, dirNone, "192.0.2.2", "198.51.100.53", 41234, 53)

	got := encode(t, render("T", k, bpf.SocketrailFlowVal{TxBytes: 40, RxBytes: 120}))

	want := `{"timestamp":"T","proto":"udp","family":"inet","remote":"198.51.100.53","remote_port":53,"local":"192.0.2.2","local_port":41234,"tx_bytes":40,"rx_bytes":120}`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestAnIPv6AddressUsesAllSixteenBytes(t *testing.T) {
	k := key(syscall.IPPROTO_TCP, dirOut, "2001:db8::2", "2001:db8::7", 0, 443)

	r := render("T", k, bpf.SocketrailFlowVal{})

	if r.Family != "inet6" || r.Remote != "2001:db8::7" || r.Local != "2001:db8::2" {
		t.Errorf("got %s %s -> %s", r.Family, r.Local, r.Remote)
	}
}
