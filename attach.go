package main

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/zinrai/socketrail/bpf"
)

type tracer struct {
	objs  bpf.SocketrailObjects
	links []link.Link
}

func attach(cgroupPath string, maxEntries uint32) (*tracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raising the memlock limit: %w", err)
	}

	spec, err := bpf.LoadSocketrail()
	if err != nil {
		return nil, fmt.Errorf("reading the BPF object: %w", err)
	}
	// Why not size these in the C source: how many distinct peers a host has
	// is a property of the host, and a recompile is the wrong way to say so.
	for _, name := range []string{"flows0", "flows1"} {
		spec.Maps[name].MaxEntries = maxEntries
	}

	t := &tracer{}
	if err := spec.LoadAndAssign(&t.objs, nil); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	hooks := []struct {
		name string
		prog *ebpf.Program
		// Why not derive it from the program's section: naming it here
		// makes a mismatch fail at attach time instead of attaching
		// somewhere harmless and recording nothing.
		attachTo ebpf.AttachType
	}{
		// Why not after the skb hooks: a connection established in between
		// would have no direction for its whole life, only ever untracked.
		{"sockops", t.objs.OnSockops, ebpf.AttachCGroupSockOps},
		{"egress", t.objs.OnEgress, ebpf.AttachCGroupInetEgress},
		{"ingress", t.objs.OnIngress, ebpf.AttachCGroupInetIngress},
	}
	for _, h := range hooks {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  h.attachTo,
			Program: h.prog,
		})
		if err != nil {
			// Why not leave the links that did attach in place and carry on:
			// egress without ingress records half of every flow, which
			// reads like a host that only ever talks.
			t.Close()
			return nil, fmt.Errorf("attaching %s to %s: %w", h.name, cgroupPath, err)
		}
		t.links = append(t.links, l)
	}
	return t, nil
}

func (t *tracer) Close() {
	for _, l := range t.links {
		l.Close()
	}
	t.objs.Close()
}
