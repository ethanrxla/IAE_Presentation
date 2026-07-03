# cloud-apigw — server-side cloud tier (Lambda + API Gateway)

A **self-contained, alternative** cloud-response path for the honeypot, vendored from an
earlier lineage of the project and re-written to this node's identity
(`pi-sensor-gateway` / Debian 13 trixie / Raspberry Pi 5 / aarch64).

## How this differs from the main tree

The main honeypot (`../upstream_sync.py`) talks to **AWS Bedrock directly** from the Pi via
boto3 (Claude Haiku 4.5): the Pi holds AWS credentials itself. Simple, but the Pi carries the keys.

This module instead puts the model call **behind AWS Lambda + API Gateway**:

```
Cowrie (unattended.py) → router.py on the Pi ──HTTPS──▶ API Gateway ▶ Lambda (lambda_function.py) ▶ Bedrock
```

- The Pi holds **no AWS credentials** — only a shared auth token (`X-Svcd-Auth` header). If the
  honeypot is captured, the attacker gets a token that only reaches a rate-limited Lambda, not
  your AWS account.
- Bedrock access, the system prompt, and the model id live **server-side** in the Lambda, so
  they can be rotated without touching the Pi.

It is a **drop-in alternative to `upstream_sync.py`**, not wired into `dispatch.py` by default.
Use one cloud path or the other.

## Layout

```
cloud-apigw/
└── src/
    ├── cloud/lambda_function.py     # the Lambda handler (calls Bedrock; auth-gated)
    ├── router/router.py             # runs on the Pi; posts commands to the API Gateway URL
    ├── router/system_prompt.txt     # the shell persona (normalized to this node's identity)
    ├── cowrie_patch/unattended.py   # Cowrie command hook that invokes the router
    └── scripts/
        ├── deploy_cloud.sh          # deploy Lambda with a Function URL
        ├── deploy_cloud_apigw.sh    # deploy Lambda behind API Gateway (REST)
        ├── install_svcd.sh          # install the router + hook onto the Pi
        └── setup_llm.sh             # provision the model/runtime
```

## Configuration (no secrets in this repo)

Everything sensitive is supplied at deploy time via environment variables — nothing is
committed here:

| Where | Variable | Purpose |
|-------|----------|---------|
| Lambda | `BEDROCK_MODEL_ID` | model to invoke (defaults to a Claude Haiku id) |
| Lambda | `SVCD_AUTH_TOKEN` | shared secret; the router must send it or the call is rejected |
| Lambda | `AWS_REGION` | Bedrock region |
| Pi router | endpoint URL + token | the API Gateway / Function URL and matching auth token |

Deploy the Lambda first (`deploy_cloud_apigw.sh`), then point the Pi router at the returned
endpoint via `install_svcd.sh`.
