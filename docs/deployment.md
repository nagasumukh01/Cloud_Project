# Deployment

Two paths. **Path A is the primary research environment and is verified.** Path B is optional,
limited, and must never introduce a paid dependency.

---

## Path A — Local deployment (verified)

### A1. Pure Python (no Docker) — the fallback that always works

```bash
git clone <your-repo-url> trustproof-cloud && cd trustproof-cloud
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # Windows: copy .env.example .env
# edit .env and set TPC_API_KEY / TPC_ADMIN_API_KEY before exposing anything

pytest tests/ -q                   # 127 tests
python scripts/demo.py             # guided walkthrough
python -m experiments.runners.mve --tasks 150 --seeds 3
```

Start the API gateway:

```bash
uvicorn services.api.main:app --host 0.0.0.0 --port 8000
# docs:   http://localhost:8000/docs
# health: http://localhost:8000/health
```

Submit a task (auth disabled locally via `TPC_REQUIRE_AUTH=false`; with auth on, add
`-H "X-API-Key: $TPC_API_KEY"`):

```bash
python - <<'PY'
import json, urllib.request
from sklearn.datasets import load_digits
X, _ = load_digits(return_X_y=True)
body = json.dumps({"features": X[0].tolist(), "sensitivity": "high"}).encode()
req = urllib.request.Request("http://localhost:8000/tasks", body,
                             {"Content-Type": "application/json"})
print(json.dumps(json.load(urllib.request.urlopen(req)), indent=2))
PY
```

**Windows notes.** Everything above works in PowerShell. Use `copy` instead of `cp`, and
`.venv\Scripts\activate`. `make` is not present by default — run the underlying commands directly,
or install GNU Make via `winget install GnuWin32.Make`. File-permission hardening in `KeyStore`
(`chmod 0700/0600`) is a no-op on Windows and is skipped without error; treat the keystore
directory as unprotected there.

### A2. Makefile shortcuts

| Command | Effect |
|---|---|
| `make install` | install core dependencies |
| `make test` | run the full suite |
| `make demo` | guided walkthrough |
| `make experiment` | six-arm MVE |
| `make api` | start the gateway on :8000 |
| `make reset` | delete DB, cached model and keys (keeps results) |
| `make clean` | reset + clear caches |
| `make docker-up` / `make docker-down` | start / tear down the container stack |

### A3. Docker Compose — authored, NOT yet executed

`Dockerfile` and `docker-compose.yml` are written and reviewed, but **have not been run in the
development environment, which has no Docker daemon.** They are therefore marked unverified. Do
not report them as working until you have run:

```bash
docker compose config        # validate
docker compose up --build    # start
curl localhost:8000/health   # confirm
docker compose down -v       # clean up (removes volumes)
```

and recorded the output.

### A4. Shutdown and cleanup

```bash
# Ctrl-C the uvicorn process, then:
make reset            # local state
docker compose down -v  # containers + volumes, if you used them
```

Nothing in this project creates a cloud resource, an account, or a billable object. There is
nothing to deprovision beyond local files and containers.

---

## Path B — Optional public demonstration

**Do this only after Path A works, and only with a clear head about the constraints.**

### What can and cannot be hosted free

| Component | Free-tier viability | Recommendation |
|---|---|---|
| Static report / charts / docs | Good — static hosting is widely free | Publish the read-only research report |
| Single-process API + a couple of in-process workers | Possible on free app tiers, but usually sleeps when idle and has a small memory ceiling | Acceptable for a *demo*, not for experiments |
| Long-running distributed workers, queues, object storage | **Not viable free.** Needs always-on processes, persistent volumes, and multiple services | Keep local |
| Experiment runs | Needs sustained CPU; free tiers throttle and time out | Keep local |
| Persistent database | Free tiers are typically ephemeral or expire | Treat as **temporary storage**, never as a system of record |

### Rules for Path B

1. **Verify against the platform's current official documentation on the day you deploy.** Free
   tiers change without notice.
2. **Never describe any third-party free tier as permanently free or risk-free.** They are subject
   to change, expiry, quota exhaustion, and idle eviction.
3. **Do not enter payment details, and do not enable any service that requires a card**, even if
   it advertises a free allowance.
4. **Do not treat a free database as durable.** Export results to the repository.
5. If the full system cannot be hosted free — which is the expected outcome — deploy a **read-only
   demonstration** (static dashboard + pre-computed results) and direct users to local Docker for
   the interactive system. This is the recommended split, not a failure.
6. Never deploy with `TPC_REQUIRE_AUTH=false`. Never commit `.env`.

### Secure configuration for any public deployment

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"   # TPC_API_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"   # TPC_ADMIN_API_KEY (different!)
python -c "import os; print(os.urandom(32).hex())"             # TPC_ARTIFACT_KEY
```

- Set `TPC_REQUIRE_AUTH=true` and both keys; `/health` reports when auth is off so a misconfigured
  gateway is visible rather than silent.
- Use distinct keys for normal and admin scopes — admin endpoints (quarantine, register) reject the
  normal key.
- Put TLS in front of the gateway (platform-provided termination is fine). The envelope protects
  result integrity, **not** transport confidentiality.
- Never mount a keystore directory into a public deployment. Worker private keys belong on workers.

## Environment variables

Full list with defaults in `.env.example` and `services/common/config.py`.

| Variable | Default | Purpose |
|---|---|---|
| `TPC_ENV` | `local` | deployment label |
| `TPC_DATA_DIR` | `./data` | database, cached model, keystore |
| `TPC_DATABASE_URL` | `sqlite:///./data/trustproof.db` | SQLAlchemy URL (Postgres-compatible) |
| `TPC_REQUIRE_AUTH` | `true` | master switch for API-key auth |
| `TPC_API_KEY` / `TPC_ADMIN_API_KEY` | *(unset)* | read/submit key and admin key |
| `TPC_ARTIFACT_KEY` | *(unset, no default)* | AES-256 key, 64 hex chars |
| `TPC_MAX_AGE_S` / `TPC_SKEW_S` | `300` / `30` | envelope freshness window |
| `TPC_TASK_TIMEOUT_MS` / `TPC_MAX_RETRIES` / `TPC_MAX_REPLICAS` | `5000` / `2` / `3` | scheduling |
| `TPC_RISK_LOW` / `TPC_RISK_HIGH` / `TPC_EXPLORE` | `0.25` / `0.60` / `0.05` | policy thresholds |
| `TPC_TRUST_ALPHA` / `TPC_TRUST_PRIOR` / `TPC_TRUST_FLOOR` | `0.15` / `0.70` / `0.25` | trust engine |
| `TPC_SEED` | `42` | reproducibility |

## Health endpoints

| Endpoint | Meaning |
|---|---|
| `GET /health` | liveness + active worker count + whether the DB is attached. Public (no key). |
| `GET /ready` | readiness: system built, model loaded, workers registered. 503 when not ready. |
| `GET /metrics` | JSON counters (Prometheus exposition format is an M7 item). Requires a key. |
