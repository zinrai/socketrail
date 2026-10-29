#!/usr/bin/env python3
"""Load socketrail into a cgroup of its own, send traffic from inside it to
this host's own address, and check the records. Run as root:

    sudo python3 scripts/smoke.py ./socketrail
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time

CGROUP = "/sys/fs/cgroup/socketrail-smoke"
failures = []

# Why not leave sockets blocking: a program that drops packets would leave the
# exchange waiting forever, and the check would hang instead of failing.
socket.setdefaulttimeout(5)


def check(ok, what, records):
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures.append(what)
        for r in records:
            print("     ", json.dumps(r))


def host_address():
    # Why not 127.0.0.1: loopback is not recorded.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("192.0.2.1", 9))
    addr = s.getsockname()[0]
    s.close()
    return addr


def tcp_exchange(family, listen_addr, connect_addr, port, v6only=True):
    srv = socket.socket(family)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, int(v6only))
    srv.bind((listen_addr, port))
    srv.listen()
    c = socket.socket(family)
    c.connect((connect_addr, port))
    a, _ = srv.accept()
    c.sendall(b"x" * 100)
    a.recv(1000)
    for s in (c, a, srv):
        s.close()


def udp_exchange(addr, port):
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind((addr, port))
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.bind((addr, 0))
    tx.sendto(b"q" * 50, (addr, port))
    rx.recvfrom(100)
    sport = tx.getsockname()[1]
    tx.close()
    rx.close()
    return sport


def record(binary, args, traffic):
    """Run socketrail, generate traffic, stop it with SIGTERM, return records."""
    p = subprocess.Popen(
        [binary, "-cgroup", CGROUP] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(1.5)
    if p.poll() is not None:
        print(p.stderr.read())
        sys.exit("socketrail exited before any traffic was sent")
    traffic()
    time.sleep(0.5)
    p.send_signal(signal.SIGTERM)
    out, err = p.communicate(timeout=10)
    if p.returncode != 0:
        print(err)
        sys.exit(f"socketrail exited with {p.returncode}")
    return [json.loads(line) for line in out.splitlines()]


def main():
    binary = os.path.abspath(sys.argv[1])
    addr = host_address()
    with open("/proc/self/cgroup") as f:
        # cgroup v2 has a single line, "0::/path".
        home = "/sys/fs/cgroup" + f.read().strip().split("::", 1)[1]
    os.makedirs(CGROUP, exist_ok=True)
    with open(os.path.join(CGROUP, "cgroup.procs"), "w") as f:
        f.write(str(os.getpid()))
    try:
        ports = {}

        def traffic():
            tcp_exchange(socket.AF_INET, addr, addr, 18080)
            ports["udp"] = udp_exchange(addr, 15353)
            tcp_exchange(socket.AF_INET6, "::", "::ffff:" + addr, 18081, v6only=False)
            tcp_exchange(socket.AF_INET, "127.0.0.1", "127.0.0.1", 18082)

        # Why -interval 1h: the only interval to close is the one SIGTERM
        # ends, which also checks that it is written out.
        rs = record(binary, ["-interval", "1h"], traffic)

        def find(**want):
            return [r for r in rs if all(r.get(k) == v for k, v in want.items())]

        out = find(proto="tcp", dir="out", remote_port=18080)
        check(
            len(out) == 1
            and "local_port" not in out[0]
            and out[0]["conns"] == 1
            and out[0]["tx_bytes"] > 0,
            "tcp out keeps only the remote port and counts one connection",
            rs,
        )
        inn = find(proto="tcp", dir="in", local_port=18080)
        check(
            len(inn) == 1
            and "remote_port" not in inn[0]
            and inn[0]["conns"] == 1
            and inn[0]["rx_bytes"] > 0,
            "tcp in keeps only the local port and counts one connection",
            rs,
        )
        udp = find(proto="udp", remote_port=15353, local_port=ports["udp"])
        check(
            len(udp) == 1
            and "dir" not in udp[0]
            and "conns" not in udp[0]
            and udp[0]["tx_bytes"] > 0,
            "udp keeps both ports and has no direction or connection count",
            rs,
        )
        mapped = find(proto="tcp", dir="out", remote_port=18081)
        check(
            len(mapped) == 1
            and mapped[0]["family"] == "inet"
            and mapped[0]["conns"] == 1
            and mapped[0]["tx_bytes"] > 0,
            "a v4-mapped connection lands on one inet line",
            rs,
        )
        check(
            not find(remote_port=18082) and not find(local_port=18082),
            "loopback is not recorded",
            rs,
        )

        def overflow():
            for port in (18090, 18091, 18092):
                tcp_exchange(socket.AF_INET, addr, addr, port)

        rs = record(binary, ["-interval", "1h", "-max-entries", "1"], overflow)
        check(
            any(r.get("dropped", 0) > 0 for r in rs), "a full table reports dropped", rs
        )
    finally:
        with open(os.path.join(home, "cgroup.procs"), "w") as f:
            f.write(str(os.getpid()))
        os.rmdir(CGROUP)

    if failures:
        sys.exit(f"{len(failures)} check(s) failed")


main()
