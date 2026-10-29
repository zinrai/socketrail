package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cilium/ebpf"

	"github.com/zinrai/socketrail/bpf"
)

const (
	cntDropped   = uint32(bpf.SocketrailCounterCNT_DROPPED)
	cntUntracked = uint32(bpf.SocketrailCounterCNT_UNTRACKED)
	cntMax       = uint32(bpf.SocketrailCounterCNT_MAX)
)

// Why not longer: programs run for microseconds, and anything that lands
// after the drain is not lost, it stays in the map for the interval after
// next.
const swapGrace = 100 * time.Millisecond

type flow struct {
	key bpf.SocketrailFlowKey
	val bpf.SocketrailFlowVal
}

// Why not take the maps directly: the swapping and reporting are the part
// worth testing, and a test cannot load a map.
type tally struct {
	setFilling func(idx uint32) error
	drain      func(idx uint32) ([]flow, error)
	counter    func(i uint32) ([]uint64, error)
	out        *json.Encoder
	grace      time.Duration

	filling uint32
	seen    [cntMax]uint64
}

func newTally(objs *bpf.SocketrailObjects, out *json.Encoder) *tally {
	maps := [2]*ebpf.Map{objs.Flows0, objs.Flows1}
	return &tally{
		setFilling: func(idx uint32) error {
			return objs.Filling.Update(uint32(0), idx, ebpf.UpdateAny)
		},
		drain: func(idx uint32) ([]flow, error) {
			return drainMap(maps[idx])
		},
		counter: func(i uint32) ([]uint64, error) {
			var perCPU []uint64
			err := objs.Counters.Lookup(i, &perCPU)
			return perCPU, err
		},
		out:   out,
		grace: swapGrace,
	}
}

func drainMap(m *ebpf.Map) ([]flow, error) {
	var (
		keys []bpf.SocketrailFlowKey
		k    bpf.SocketrailFlowKey
		v    bpf.SocketrailFlowVal
	)
	// Why not delete while walking: deleting from a hash map during the walk
	// can make it restart or skip.
	it := m.Iterate()
	for it.Next(&k, &v) {
		keys = append(keys, k)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("walking %s: %w", m, err)
	}

	flows := make([]flow, 0, len(keys))
	for _, k := range keys {
		f, ok, err := takeFlow(m, k)
		if err != nil {
			return nil, err
		}
		if ok {
			flows = append(flows, f)
		}
	}
	return flows, nil
}

// Why not keep the value the walk already returned: a late write between the
// walk and the delete would be thrown away, and this way it is in the value
// read.
func takeFlow(m *ebpf.Map, k bpf.SocketrailFlowKey) (flow, bool, error) {
	var v bpf.SocketrailFlowVal
	err := m.LookupAndDelete(&k, &v)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return flow{}, false, nil
	}
	if err != nil {
		return flow{}, false, fmt.Errorf("draining %s: %w", m, err)
	}
	return flow{k, v}, true, nil
}

func (t *tally) tick() error {
	old := t.filling
	next := old ^ 1
	if err := t.setFilling(next); err != nil {
		return fmt.Errorf("switching flow maps: %w", err)
	}
	t.filling = next
	ts := time.Now().UTC().Format(stampFormat)
	// Why not drain straight after switching: a program that read the old
	// index just before the switch may still be adding to the old map.
	time.Sleep(t.grace)

	flows, err := t.drain(old)
	if err != nil {
		// Why not log and carry on: the undrained rows are still there when
		// the programs come back to this map, and would be reported again.
		return err
	}
	// Why not write in map order: the map walks in hash order, and two
	// intervals of the same traffic should read the same way top to bottom.
	slices.SortFunc(flows, compareFlows)
	for _, f := range flows {
		if err := t.out.Encode(render(ts, f.key, f.val)); err != nil {
			return fmt.Errorf("writing a record: %w", err)
		}
	}
	return t.reportCounters(ts)
}

func (t *tally) reportCounters(ts string) error {
	rec := counterRecord{TS: ts}
	changed := false
	for i, field := range []*uint64{&rec.Dropped, &rec.Untracked} {
		perCPU, err := t.counter(uint32(i))
		// Why not write a zero when a read fails: claiming nothing was
		// dropped because the counter could not be read is worse than
		// silence.
		if err != nil {
			continue
		}
		if n, ok := delta(perCPU, &t.seen[i]); ok {
			*field = n
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := t.out.Encode(rec); err != nil {
		return fmt.Errorf("writing a record: %w", err)
	}
	return nil
}

// Why not report the running total: a reader that missed an earlier record
// could not tell how much of the total it had already seen, while differences
// add up whatever arrives.
func delta(perCPU []uint64, seen *uint64) (uint64, bool) {
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	if total == *seen {
		return 0, false
	}
	n := total - *seen
	*seen = total
	return n, true
}

func compareFlows(a, b flow) int {
	x, y := a.key, b.key
	if c := cmp.Compare(x.Proto, y.Proto); c != 0 {
		return c
	}
	if c := cmp.Compare(x.Dir, y.Dir); c != 0 {
		return c
	}
	if c := cmp.Compare(x.Family, y.Family); c != 0 {
		return c
	}
	if c := bytes.Compare(x.Raddr[:], y.Raddr[:]); c != 0 {
		return c
	}
	if c := cmp.Compare(x.Rport, y.Rport); c != 0 {
		return c
	}
	if c := bytes.Compare(x.Laddr[:], y.Laddr[:]); c != 0 {
		return c
	}
	return cmp.Compare(x.Lport, y.Lport)
}
