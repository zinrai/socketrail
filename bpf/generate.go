// Package bpf holds the BPF program and what bpf2go generates from it.
package bpf

// Why not write the loader and the Go form of the BPF types by hand: what is
// copied out of C drifts the moment either side changes, and bpf2go takes both
// from the same BTF.
//
//go:generate go tool bpf2go -type flow_key -type flow_val -type counter -type dir Socketrail socketrail.bpf.c
