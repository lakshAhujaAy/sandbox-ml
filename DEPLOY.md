# Deploying MalSandbox ML (always-on URL, no localhost)

One container runs everything: dashboard, API, Redis, the ML worker (URL model,
behavior model, Vision CNN) and headless Chromium for the sandbox.

```bash
docker build -t malsandbox .
docker run -d --restart unless-stopped -p 80:7860 \
  -e BASIC_AUTH_PASSWORD=choose-a-password malsandbox
```

Then open `http://<host>/` (user `admin`). Check the real stack is live:

```bash
python scripts/smoke_test.py http://<host> --password choose-a-password
```

It fails unless the ML worker is up, **all three trained models loaded** (not the
rule-based fallback) and a real job completes. The dashboard header shows the same
status, and `GET /health` is left open for host health checks.

## Where to host it

| Option | Notes |
|---|---|
| **Any VPS/VM with Docker** (simplest) | Use the commands above. Add HTTPS with `caddy reverse-proxy --from your.domain --to localhost:7860`. |
| **Render / Railway / Fly.io** (deploy a Dockerfile from GitHub) | Point at this repo, set `PORT=7860` and the password. The image needs a plan with enough RAM: my estimate is 2 GB or more (torch + Chromium), not measured, and 512 MB free tiers won't fit. |
| **Hugging Face Space (Docker)** | Needs `sdk: docker` and `app_port: 7860` front matter in the Space's README, and the 43 MB model file needs Git LFS. Their docs currently say compute Spaces require a paid plan, so check before relying on it. |

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `BASIC_AUTH_PASSWORD` / `BASIC_AUTH_USER` | unset / `admin` | Shared password for the dashboard and API. **Set it on any public deployment.** |
| `MAX_WORKERS` | 2 | Concurrent sandbox browsers (each uses roughly a few hundred MB). |
| `SANDBOX_TIMEOUT` / `ML_TIMEOUT` | 45 / 60 s | Per-job limits. |
| `PORT` | 7860 | Port inside the container. |

## Know before you expose it

- **Isolation is the container.** Hosted mode runs the sandbox browser as a child
  process in the same container rather than a fresh container per URL (hosts don't
  allow Docker-in-Docker). Run it on a throwaway host and keep nothing else on it.
- **It visits live malicious sites from the host's IP address.**
- Targets must be public http(s) URLs, and the sandbox browser blocks requests to
  private/internal addresses. A DNS-rebinding attack between the check and the
  browser's lookup is a known remaining gap.
- State is in memory: jobs and results are lost when the container restarts.
- First start takes a while: the worker loads torch before `ml_worker` shows `up`.
- Vision accuracy caveat is unchanged: it was trained on synthetic screenshots
  (see `backend/ml/vision/TRAINING_NOTES.md`).
