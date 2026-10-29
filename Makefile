# Requirements: a Go toolchain, and clang only to rebuild the BPF program.
#
#   sudo apt install clang llvm libbpf-dev make golang-go
BPF2GO_CFLAGS := -O2 -g -Wall -I/usr/include/$(shell uname -m)-linux-gnu

BPF_SRC := bpf/socketrail.bpf.c
BPF_OBJ := bpf/socketrail_bpfel.o

all: socketrail

# The object is a prerequisite, not a note in the README: `go build` embeds
# whatever is committed, so editing bpf/ and forgetting to regenerate would
# leave you running the previous program while everything looks fine.
socketrail: $(wildcard *.go) $(wildcard bpf/*.go) $(BPF_OBJ)
	go build -o $@ .

$(BPF_OBJ): $(BPF_SRC) bpf/generate.go
	BPF2GO_CFLAGS="$(BPF2GO_CFLAGS)" go generate ./...

# Commit what this produces. It is what lets `go build` work without clang.
generate:
	BPF2GO_CFLAGS="$(BPF2GO_CFLAGS)" go generate ./...

clean:
	rm -f socketrail

.PHONY: all generate clean
