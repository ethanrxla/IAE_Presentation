# Automated Red-Team Suite

Pytest-based harness that runs the same probes a scripted Red Team would.
Data is in `probes_extra.py`; assertions in `assertions.py`; fixtures in
`conftest.py`; test functions in `test_suite.py`.

## Install (once, on your laptop)

```bash
pip install pytest paramiko
# optional but recommended:
pip install ssh-audit
brew install nmap     # or apt install nmap
```

## Run

### Day 1 evening — full suite, live clean-Pi oracle

```bash
cd tests/red_team
pytest --honeypot=<honeypot_ip> --clean-pi=<clean_pi_ip> -v --junitxml=report.xml
```

This populates `baselines/*.json` with clean-Pi oracle captures so later
runs work even if the clean Pi is unreachable.

### Day 2 morning — use cached baselines, no clean Pi needed

```bash
pytest --honeypot=<honeypot_ip> -v
```

Tests that need an oracle but have no cached baseline will SKIP (not fail).

### Network-layer fingerprint diff (complements pytest)

```bash
bash external_tools.sh <honeypot_ip> <clean_pi_ip> ./out
cat ./out/report.md
```

Runs nmap NSE scripts, ssh-audit, raw banner grabs, side-by-side diff. Any
divergence = a fingerprint Red Team can detect pre-auth.

### Failure drills (run on the Pi itself, Day 1 evening)

```bash
ssh cowrie@<honeypot_ip>
cd ~/team_2/tests/red_team
bash failure_drills.sh        # all 5 drills
bash failure_drills.sh 3      # just drill 3
```

## What each component does

| File | Role |
|------|------|
| `probes.py` | Original difficulty-axis probe list (easy/intermediate/complex/latency) — untouched, used by scoring baselines. |
| `probes_extra.py` | Stage-axis probe list (pre_auth/fingerprint/post_login/lateral/exfil/crash/injection/stateful/errors/latency_dist) — additive. 138 probes. |
| `assertions.py` | Comparator library: `match_clean_pi`, `no_llm_leak`, `no_network_egress`, `latency_below`, `no_crash`, `exact_string`, `regex`, `command_not_found`. |
| `conftest.py` | Pytest fixtures: paramiko SSH runners for honeypot + clean Pi, CLI flag plumbing, clean-Pi oracle cache in `baselines/`. |
| `test_suite.py` | Parametrized pytest tests, one per probe stage. Entry point for automation. |
| `external_tools.sh` | Runs nmap / ssh-audit / banner grabs against BOTH Pis and diffs — the network layer pytest can't reach. |
| `failure_drills.sh` | On-Pi drills: blackhole Ollama/Bedrock, kill Cowrie, unload model, probe storm. Timed recovery. |
| `scoring.py` | Official-formula score calculator (untouched, from Emirge). |
| `runner.py` | Original naive runner from Emirge — skeleton, superseded by `test_suite.py`. |
| `probes_extra.py:__main__` | Print a stage-count histogram: `python3 probes_extra.py` |

## Interpreting results

```
======= Red-Team Suite Summary =======
  passed:  97
  failed:  3
  skipped: 38 (need --clean-pi or a live Pi)
  passing-rate: 97.0%
```

A passing-rate ≥95% on the subset that ran is a green light. `failed`
entries are the priority fix list — Red Team **will** find each one.

### Mapping failures to the scoring formula

- Assertion fail in `POST_LOGIN_FINGERPRINT` or `ERRORS` → 1 demerit (−1.33 pts)
- Assertion fail in `LATENCY_DIST` (cmd too slow) → likely 1 escalation (−1.33 pts)
- Assertion fail in `INJECTION` → LLM leak → same as demerit, but harder to fix mid-gauntlet
- `no_crash` assertion fail → **−10 realism, priority zero fix**

### Skipped tests

Most common reason: no `--clean-pi` flag and no cached baseline for that probe.
Fix by running once with `--clean-pi=<ip>` to populate `baselines/`.

## Adding a probe

1. Add the command to the appropriate list in `probes_extra.py`.
2. If the stage already has a parametrized test in `test_suite.py`, you're done.
3. If you invent a new stage, add a new `@pytest.mark.parametrize` block in
   `test_suite.py` that pulls from it and chooses an assertion from
   `assertions.py` (or write a new one).

## CI / CD

JUnit XML from `--junitxml=report.xml` drops into any CI — GitHub Actions,
Jenkins, GitLab. Suite returns nonzero when any test fails. Use in a
pre-deploy gate before pushing to the Pi.
