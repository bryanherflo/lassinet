# Benchmarks and honest performance limits

LassiNet has **two different performance paths** and they must not be mixed:

1. **Capture** (scapy/Python, one interface).
2. **Detector** (feature extraction + ML/rules on flow dicts).

The repository includes `scripts/benchmark.py` for path 2. It is synthetic and
does not claim NIC/gigabit performance.

## Detector throughput

```bash
python scripts/benchmark.py --flows 5000 --rounds 3
```

Record the machine (CPU, RAM, OS, Python), model (`demo`/CICIDS), and the
output. A result of tens of thousands of flows/s means the detector is not the
bottleneck for a home network; it says nothing about packet capture.

## Capture path

Use a real pcap and an external tool:

```bash
# Linux: replay a capture into an isolated lab interface (authorized lab only)
sudo tcpreplay --intf=eth1 --pps=5000 capture.pcap

# Meanwhile, observe:
curl -s http://127.0.0.1:8000/metrics | grep lassinet_
```

Measure CPU, dropped packets (`ifconfig`/`ethtool -S`/Npcap stats), and
`lassinet_flows_per_sec`. For multi-gigabit traffic, use Suricata/Zeek on a
SPAN/mirror and feed LassiNet the EVE/logs; do not put Python in the packet
path.

## Scaling rules of thumb

- Keep `LASSI_CAPTURE_FILTER` narrow (`tcp or udp`, exclude backup traffic).
- Use `LASSI_PASSIVE=1` where active probes are not authorized.
- Keep the alert feed bounded (200 cards) and the log retention bounded.
- SQLite triage is single-process; one writer is enough.
- On a switched LAN, use a SPAN/mirror port or run on the gateway; a host
  sniffer sees only its own traffic plus broadcast.

## What is not benchmarked here

- HA/failover.
- Multi-sensor aggregation.
- Line-rate DPI.
- Formal latency/SLA guarantees.

Those are out of scope and should be evaluated with the tools that own them
(Suricata/Zeek/OPNsense), not with this project’s Python sensor.
