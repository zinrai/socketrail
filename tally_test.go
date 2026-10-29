package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/zinrai/socketrail/bpf"
)

type fakeMaps struct {
	filling  []uint32
	flows    [2][]flow
	counters [cntMax][]uint64
	failRead [cntMax]bool
	drained  []uint32
}

func newFakeTally(m *fakeMaps, out *bytes.Buffer) *tally {
	return &tally{
		setFilling: func(idx uint32) error {
			m.filling = append(m.filling, idx)
			return nil
		},
		drain: func(idx uint32) ([]flow, error) {
			m.drained = append(m.drained, idx)
			f := m.flows[idx]
			m.flows[idx] = nil
			return f, nil
		},
		counter: func(i uint32) ([]uint64, error) {
			if m.failRead[i] {
				return nil, errors.New("unreadable")
			}
			return m.counters[i], nil
		},
		out:   json.NewEncoder(out),
		grace: 0,
	}
}

func tick(t *testing.T, tl *tally) {
	t.Helper()
	if err := tl.tick(); err != nil {
		t.Fatal(err)
	}
}

func TestEachTickSwitchesMapsThenDrainsTheOldOne(t *testing.T) {
	m := &fakeMaps{}
	tl := newFakeTally(m, &bytes.Buffer{})

	tick(t, tl)
	tick(t, tl)
	tick(t, tl)

	if got := m.filling; len(got) != 3 || got[0] != 1 || got[1] != 0 || got[2] != 1 {
		t.Errorf("switched to %v, want [1 0 1]", got)
	}
	if got := m.drained; len(got) != 3 || got[0] != 0 || got[1] != 1 || got[2] != 0 {
		t.Errorf("drained %v, want [0 1 0]", got)
	}
}

func TestADrainedFlowIsWrittenOnceAndSorted(t *testing.T) {
	var out bytes.Buffer
	m := &fakeMaps{}
	m.flows[0] = []flow{
		{key(syscall.IPPROTO_UDP, dirNone, "192.0.2.2", "192.0.2.9", 1000, 53), bpf.SocketrailFlowVal{TxBytes: 1}},
		{key(syscall.IPPROTO_TCP, dirOut, "192.0.2.2", "192.0.2.9", 0, 443), bpf.SocketrailFlowVal{Conns: 1}},
		{key(syscall.IPPROTO_TCP, dirOut, "192.0.2.2", "192.0.2.3", 0, 443), bpf.SocketrailFlowVal{Conns: 1}},
	}
	tl := newFakeTally(m, &out)

	tick(t, tl)
	tick(t, tl)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d records, want 3:\n%s", len(lines), out.String())
	}
	for i, want := range []string{`"remote":"192.0.2.3"`, `"remote":"192.0.2.9","remote_port":443`, `"proto":"udp"`} {
		if !strings.Contains(lines[i], want) {
			t.Errorf("line %d = %s, want it to contain %s", i, lines[i], want)
		}
	}
}

func TestCountersAreReportedOnlyWhenTheyMove(t *testing.T) {
	var out bytes.Buffer
	m := &fakeMaps{}
	tl := newFakeTally(m, &out)

	m.counters[cntDropped] = []uint64{0, 0}
	m.counters[cntUntracked] = []uint64{2, 1}
	tick(t, tl)
	tick(t, tl)
	m.counters[cntDropped] = []uint64{4, 1}
	tick(t, tl)

	var got []counterRecord
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var r counterRecord
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatal(err)
		}
		r.TS = ""
		got = append(got, r)
	}
	want := []counterRecord{{Untracked: 3}, {Dropped: 5}}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestAnUnreadableCounterIsNotReportedAsZero(t *testing.T) {
	var out bytes.Buffer
	m := &fakeMaps{}
	m.counters[cntDropped] = []uint64{2}
	tl := newFakeTally(m, &out)
	tick(t, tl)
	out.Reset()

	m.failRead[cntDropped] = true
	m.counters[cntUntracked] = []uint64{1}
	tick(t, tl)

	if strings.Contains(out.String(), "dropped") {
		t.Errorf("an unreadable counter was reported: %s", out.String())
	}
}

func TestTheFirstReadCountsEverythingSoFar(t *testing.T) {
	var seen uint64

	n, ok := delta([]uint64{3, 4, 0, 1}, &seen)

	if !ok || n != 8 {
		t.Errorf("first read = %d/%v, want 8/true", n, ok)
	}
}

func TestEachReadReportsOnlyWhatWasAdded(t *testing.T) {
	var seen uint64
	delta([]uint64{3, 4, 0, 1}, &seen)

	n, ok := delta([]uint64{3, 9, 0, 1}, &seen)

	if !ok || n != 5 {
		t.Errorf("second read = %d/%v, want 5/true", n, ok)
	}
}
