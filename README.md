# socketrail

Records, once per interval, which peers this host exchanged TCP and UDP traffic with, as JSON Lines.

```
{"timestamp":"2026-10-29T00:01:00.000Z","proto":"tcp","dir":"out","family":"inet","remote":"198.51.100.10","remote_port":443,"local":"192.0.2.2","conns":12,"tx_bytes":18342,"rx_bytes":402113}
{"timestamp":"2026-10-29T00:01:00.000Z","proto":"tcp","dir":"out","family":"inet","remote":"198.51.100.20","remote_port":443,"local":"192.0.2.2","conns":0,"tx_bytes":95,"rx_bytes":95}
{"timestamp":"2026-10-29T00:01:00.000Z","proto":"tcp","dir":"in","family":"inet","remote":"198.51.100.31","local":"192.0.2.2","local_port":22,"conns":1,"tx_bytes":5120,"rx_bytes":3488}
{"timestamp":"2026-10-29T00:01:00.000Z","proto":"udp","family":"inet","remote":"198.51.100.53","remote_port":53,"local":"192.0.2.2","local_port":41877,"tx_bytes":64,"rx_bytes":128}
```

One line per peer and service per interval, not per connection or per packet. The number of lines grows with how many peers the host has, not with how busy it is.

It never holds the packet path: the programs only count, and when the table of an interval fills up, what is lost is a count, which is reported, never a packet.

## Reading a record

`timestamp` is the end of the interval the record covers.

**TCP** records say who opened the connection. `dir` is `out` when this host called `connect()` and `in` when it accepted. The port on the side that opened the connection is new on every connection, so it is not kept:

```
{"dir":"out","remote":"198.51.100.10","remote_port":443}   this host to their 443
{"dir":"in","remote":"198.51.100.31","local_port":22}      them to this host's 22
```

`conns` is the number of connections established during the interval. `"conns":0` with bytes means traffic on a connection opened earlier.

**UDP** records have no `dir`, because UDP does not say which side is the client, and keep both ports instead. A client that picks a new source port per request produces a line per port.

`tx_bytes` and `rx_bytes` are IP-layer bytes from this host's point of view, counted from the moment a TCP connection is established.

## Counters

A second kind of record reports what could not be attributed:

```
{"timestamp":"2026-10-29T00:01:00.000Z","dropped":72}
{"timestamp":"2026-10-29T00:01:00.000Z","untracked":4}
```

It appears only when something happened, carries the number since the previous one, and has no `remote`.

**`dropped`** counts updates that found the interval's table full. Raise `-max-entries` or shorten `-interval`.

**`untracked`** counts packets on TCP connections established before socketrail started. Which side opened them can no longer be known, so they are not recorded until they reconnect.

## Run

```
$ sudo ./socketrail
$ ./socketrail -version
```

To keep it running, see `examples/socketrail.service`.

`-max-entries` is how many distinct lines one interval can hold. Two tables of that size exist at once, roughly 100 bytes per entry each.

SIGTERM ends the interval in progress early and writes it out.

## Limits

Only traffic to and from local sockets is seen. Routed and bridged traffic passing through the host is not.

Loopback (`127.0.0.0/8`, `::1`) is not recorded. Traffic to one of the host's own other addresses also goes over loopback, and is recorded twice, once from each socket.

Sockets in another network namespace are recorded with the addresses they see, before any NAT.

IPv4 fragments after the first, and IPv6 packets with extension headers, carry no ports where this looks and are skipped.

A program that was mid-update when an interval closed may land its bytes in the interval after the next one. They are delayed, not lost.

## Requires

- root
- cgroup v2 mounted
- a kernel built with `CONFIG_CGROUP_BPF=y`
- Linux 5.14 or later, for lookup-and-delete on a hash map, which draining a table uses

## Changing the BPF program

```
$ sudo apt install clang llvm libbpf-dev make
$ make               # regenerates bpf/ when the BPF source is newer, then builds
```

Commit what that produces. The committed object is what `go build` embeds, what `go install` gets, and what a release ships.

`scripts/smoke.py` loads a build into a cgroup of its own, sends traffic to this host's own address, and checks the records. CI runs it on every change, and it runs the same way on a host:

```
$ sudo python3 scripts/smoke.py ./socketrail
```

## License

This project is licensed under the [MIT License](LICENSE).
