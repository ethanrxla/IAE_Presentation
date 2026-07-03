# Project SCALPEL — Tiered AI Honeypot

**eMERGE 2026 Hackathon · Team 07 · Miami Beach**

A high-interaction SSH honeypot built on [Cowrie](https://docs.cowrie.org/) that makes a
Raspberry Pi look like a real, lived-in Linux server to an attacker — while spending as little
compute as possible. Every command an attacker types is routed to exactly one **dispatch level**,
chosen to maximize believability and minimize cost.

This repo holds both the honeypot code and the project presentation.

- **[`index.html`](index.html)** — the project presentation (open in a browser).
- **[`honeypot/`](honeypot/)** — the honeypot agent, deployment scripts, docs, playbook, and the
  red-team test harness.

---

## The core idea: one router, no fall-through

A single classifier assigns each command to one dispatch level. There is no slow fall-through
chain — if the primary level fails, exactly one backup is tried, then a safe stub.

```
                    ┌────────────────────────┐
                    │      dispatch.py       │
                    │  classify() → ONE      │
                    │     DispatchLevel      │
                    └───────────┬────────────┘
        ┌─────────────┬─────────┼──────────┬─────────────┐
        ▼             ▼         ▼          ▼             ▼
   LOCAL_CACHE   LOCAL_RUNTIME  EDGE_INFER  CLOUD_SYNC   FALLBACK
   telemetry_    node_          edge_       upstream_    (inline stub)
   cache.py      runtime.py     inference   sync.py
   ~0.1 ms       ~1–5 ms        1–3 s       3–8 s        instant
   invariant     generated      local LLM   cloud LLM    safe default
   outputs       from state    (Ollama)    (Bedrock)
```

| Level | What it handles | Backing |
|-------|-----------------|---------|
| `LOCAL_CACHE` | Invariant outputs (`uname`, `/etc/os-release`, config-file reads, version strings, …) | static table (~160 entries) |
| `LOCAL_RUNTIME` | Stateful commands derived from session state (`uptime`, `cd`/`pwd`, `ps`, created files) | generator |
| `EDGE_INFER` | Unpredictable but cheap-to-fake commands | local LLM (Ollama) |
| `CLOUD_SYNC` | Complex/rare recon needing the strongest model | cloud LLM (AWS Bedrock) |
| `FALLBACK` | Anything that errors — never crash the shell | inline stub |

The honeypot presents as a Raspberry Pi "sensor gateway" (`pi-sensor-gateway`, Debian 11
bullseye, armv7l). Its stateful layer keeps that identity consistent under probing: `uptime`
advances on wall-clock, `cd /tmp; pwd` persists, `touch x; ls` shows the new file, and process
lists include the attacker's own shell.

### A note on the neutral filenames

The agent modules use deliberately mundane, production-looking names (`telemetry_cache.py`,
`node_runtime.py`, `edge_inference.py`, `upstream_sync.py`, `dispatch.py`, `shell_broker.py`) so
that an attacker who enumerates the real OS doesn't immediately see "honeypot tooling." The cover
story is a generic distributed-sensor node.

---

## Layout

```
honeypot/
├── dispatch.py            # classifier + metrics + fallback stub (the router)
├── telemetry_cache.py     # LOCAL_CACHE — static, invariant responses
├── node_runtime.py        # LOCAL_RUNTIME — stateful command generator
├── node_context.py        # per-session state (login time, cwd, fake procs, file table)
├── edge_inference.py      # EDGE_INFER — local Ollama client + system prompt
├── upstream_sync.py       # CLOUD_SYNC — AWS Bedrock client (direct-from-Pi)
├── shell_broker.py        # Cowrie integration hook
├── shell_layer.py         # shell parsing / command handling
├── cloud-apigw/           # alternative cloud tier: Lambda + API Gateway (self-contained)
├── bait.sh                # populates the honeyfs with realistic decoy files
├── install_ollama.sh      # installs Ollama, pulls + warms the model
├── health_check.sh        # pre-run verification
├── backup/                # snapshot / restore / USB-offline backup helpers
├── scripts/               # capture, ingest, keepalive, watchdog, opsec-verify helpers
├── dashboard/             # live metrics monitor
├── fs_assets/             # honeyfs asset notes
├── docs/                  # ARCHITECTURE, COMMANDERS_INTENT, DISASTER_RECOVERY, SCORING + flowchart
├── playbook/              # step-by-step run-of-show
└── tests/red_team/        # red-team probe harness + scoring
```

## Running the test harness

The red-team harness scores realism and efficiency without needing Ollama or AWS:

```bash
cd honeypot
python -m pytest tests/red_team -q
```

You can also exercise the classifier directly (no LLM/cloud required):

```bash
python honeypot/dispatch.py
```

---

*This repository consolidates the team's work from the hackathon. Internal notes, operational
security documents, and event materials have been intentionally omitted.*
