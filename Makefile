BPF2GO_CFLAGS := -O2 -g -Wall -I/usr/include/$(shell uname -m)-linux-gnu

BPF_SRC := bpf/socketrail.bpf.c bpf/generate.go
BPF_OBJ := bpf/socketrail_bpfel.o
# Why not have CI regenerate the objects and compare them: another clang or
# other headers compile the same source to different bytes. A hash of what the
# objects were generated from says whether they are current without either.
BPF_SUM := bpf/sources.sha256
GENERATE = BPF2GO_CFLAGS="$(BPF2GO_CFLAGS)" go generate ./... && sha256sum $(BPF_SRC) > $(BPF_SUM)

all: socketrail

# The object is a prerequisite, not a note in the README: `go build` embeds
# whatever is committed, so editing bpf/ and forgetting to regenerate would
# leave you running the previous program while everything looks fine.
socketrail: $(wildcard *.go) $(wildcard bpf/*.go) $(BPF_OBJ)
	go build -o $@ .

$(BPF_OBJ): $(BPF_SRC)
	$(GENERATE)

# Why not leave the objects out of git and generate them at build time:
# `go build` and `go install` would then need clang on every machine.
generate:
	$(GENERATE)

clean:
	rm -f socketrail

.PHONY: all generate clean
