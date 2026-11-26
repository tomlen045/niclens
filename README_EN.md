# niclens — read-only network config lens

One read-only pass answers: **"Is this machine's network configuration itself sick?"**
Interfaces/routes, DNS, hosts — three layers, 15 verdicts, cron-ready exit codes.

## Why

- After a migration, "some hosts work, some don't" — turns out one static gateway was out of subnet
- VPN up, intranet unreachable — two default routes fighting each other
- NIC swapped, the old interface still holds a static IP while DOWN
- hosts edited during "quick debugging" six months ago, nobody remembers

`ping` tells you *now*; `ifconfig` shows raw parameters. Nobody judges whether the
**configuration itself is sane** — that's what niclens does.

## Quick start

```bash
python3 niclens.py              # full checkup (macOS / Linux, no root)
python3 niclens.py --json       # machine-readable, pipe into cron/webhook
python3 niclens.py --probe      # one UDP53 probe per nameserver (3s timeout)
python3 niclens.py --demo       # sandbox demo with 4 planted faults
python3 niclens.py --save-baseline base.json
python3 niclens.py --baseline base.json   # NL-90/91 drift verdicts
```

| exit | meaning |
|---|---|
| 0 | clean |
| 1 | P2 only |
| 2 | has P1 |
| 3 | has P0 |

## Verdicts

NL-01 no default gateway / NL-02 conflicting gateways / NL-03 gateway outside subnets /
NL-04 gateway == own IP / NL-05 localhost hijacked in hosts / NL-06 no DNS /
NL-07 bogus DNS / NL-08 multi-IP hostname / NL-09 DOWN iface holding IP /
NL-10 low MTU / NL-11 duplicate nameserver / NL-12 hosts bad lines /
NL-13 too many search domains / NL-90 gateway/DNS drift vs baseline / NL-91 IP/route drift.

## Design invariants

Read-only (zero traffic except `--probe`) · stdlib-only single file · no root ·
graceful NOTE degradation on parse failure · exit-code severity mapping.

Full details in [README.md](README.md) (Chinese). MIT license.
