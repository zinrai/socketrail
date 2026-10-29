package main

import (
	"net/netip"
	"syscall"

	"github.com/zinrai/socketrail/bpf"
)

const (
	dirNone = uint8(bpf.SocketrailDirDIR_NONE)
	dirOut  = uint8(bpf.SocketrailDirDIR_OUT)
	dirIn   = uint8(bpf.SocketrailDirDIR_IN)
)

// Why not local first: which peer it was is what the record is for, and the
// local side is mostly the same handful of addresses on every line.
type record struct {
	TS     string `json:"timestamp"`
	Proto  string `json:"proto"`
	Dir    string `json:"dir,omitempty"`
	Family string `json:"family"`
	Remote string `json:"remote"`
	// Why not always write the ports: on TCP a zero is what is left where the
	// ephemeral side was dropped, and would read as port 0, not "not kept".
	RemotePort uint16  `json:"remote_port,omitempty"`
	Local      string  `json:"local"`
	LocalPort  uint16  `json:"local_port,omitempty"`
	Conns      *uint64 `json:"conns,omitempty"`
	TxBytes    uint64  `json:"tx_bytes"`
	RxBytes    uint64  `json:"rx_bytes"`
}

const stampFormat = "2006-01-02T15:04:05.000Z"

// Why not stderr for the counters: whatever collects the records
// would then hold them without the gaps, and a record set that cannot say
// whether it is complete is not worth much.
type counterRecord struct {
	TS        string `json:"timestamp"`
	Dropped   uint64 `json:"dropped,omitempty"`
	Untracked uint64 `json:"untracked,omitempty"`
}

func render(ts string, k bpf.SocketrailFlowKey, v bpf.SocketrailFlowVal) record {
	family := "inet"
	if k.Family == syscall.AF_INET6 {
		family = "inet6"
	}

	r := record{
		TS:         ts,
		Proto:      "tcp",
		Family:     family,
		Remote:     addrString(k.Family, k.Raddr),
		RemotePort: k.Rport,
		Local:      addrString(k.Family, k.Laddr),
		LocalPort:  k.Lport,
		TxBytes:    v.TxBytes,
		RxBytes:    v.RxBytes,
	}

	switch k.Dir {
	case dirOut:
		r.Dir = "out"
	case dirIn:
		r.Dir = "in"
	}

	// Why not a plain uint64: on TCP "conns":0 is an answer, traffic on
	// connections opened earlier, while on UDP there is no connection to count
	// and the field should not appear at all.
	if k.Proto == syscall.IPPROTO_UDP {
		r.Proto = "udp"
	} else {
		c := v.Conns
		r.Conns = &c
	}
	return r
}

// Why not read all sixteen bytes regardless of family: a v4 address sits in
// the first four, and the trailing zeroes would turn 192.0.2.1 into
// c000:201::.
func addrString(family uint8, b [16]uint8) string {
	if family == syscall.AF_INET6 {
		return netip.AddrFrom16(b).String()
	}
	return netip.AddrFrom4([4]byte(b[:4])).String()
}
