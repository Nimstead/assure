# Configuration

Nimstead Assure is configured with environment variables. With Docker Compose, put them in `.env` (see [`.env.example`](../.env.example)); anything not already listed in [`compose.yaml`](../compose.yaml) goes under `x-app: environment:` there, so the app and the feed updater both get it.

## Server

| Variable | Default | What it does |
|---|---|---|
| `NIMSTEAD_PUBLIC_URL` | the request's own address | The address agents and browsers use, such as `https://assure.example.com`. Baked into the agent install scripts and SSO callbacks. Set it in production. |
| `NIMSTEAD_DB` | `sqlite:///./nimstead.db` | Database URL. Use `postgresql+psycopg://user:pass@host/db` in production and run `alembic upgrade head` (the Docker image does this on start). |
| `NIMSTEAD_SECURE_COOKIES` | `1` | `0` allows sign-in over plain HTTP from a non-localhost address. Development only. |
| `NIMSTEAD_ALLOWED_ORIGINS` | none | Extra comma-separated origins allowed to make changes (the same origin always is). |
| `NIMSTEAD_INVENTORY_MIN_SECONDS` | `30` | Minimum gap between two inventories from one agent. |
| `NIMSTEAD_UPDATE_CHECK` | `1` | `0` stops the hourly feed run from asking GitHub for new releases and fetching the signed release files agents update from. Offline installs: copy `release.json` and `release.json.sig` from the release page into `NIMSTEAD_RELEASE_DIR` instead. |
| `NIMSTEAD_RELEASE_DIR` | `./release` (`/data/release` in Docker) | Signed release files, the release check's state and `deploy/update.sh`'s last result. Agents only update when this holds a release signed for the agent the server serves. |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Read by uvicorn: the reverse proxy whose `X-Forwarded-For` is trusted, so sign-in throttling sees real client addresses. |

## Keys and evidence storage

Without Vault, keys are files on disk. That's fine for evaluation; for production use Vault so keys never leave it.

| Variable | Default | What it does |
|---|---|---|
| `NIMSTEAD_VAULT_ADDR`, `NIMSTEAD_VAULT_TOKEN` | none | Use Vault transit for evidence signing, the SSO secret and domain tokens. |
| `NIMSTEAD_VAULT_MOUNT` | `transit` | Transit mount path. |
| `NIMSTEAD_VAULT_SIGNING_KEY` | `nimstead-evidence` | Ed25519 key that signs evidence packs and checkpoints. |
| `NIMSTEAD_VAULT_SECRET_KEY` | `nimstead-secrets` | Key for encryption and HMAC. |
| `NIMSTEAD_SIGNING_KEY_FILE` | `./nimstead-signing.pem` (`/data/…` in Docker) | On-disk signing key, created on first use. |
| `NIMSTEAD_SECRET_KEY_FILE` | `./nimstead-secret.key` (`/data/…` in Docker) | On-disk secret key, created on first use. |
| `NIMSTEAD_CHECKPOINT_DIR` | `./checkpoints` (`/data/…` in Docker) | Where signed ledger checkpoints go without S3. |
| `NIMSTEAD_CHECKPOINT_S3` | none | `s3://bucket/prefix` for write-once checkpoints. Create the bucket with object lock. |
| `NIMSTEAD_S3_ENDPOINT` | AWS | Endpoint for S3-compatible storage. |
| `NIMSTEAD_CHECKPOINT_RETAIN_DAYS` | `3650` | Object-lock retention per checkpoint. |

Publish your evidence key fingerprint (`GET /api/evidence/public-key`) to auditors through a channel other than the evidence pack itself.

## Remediation

| Variable | Default | What it does |
|---|---|---|
| `NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION` | off | `1` lets fixes target hosts that weren't enrolled with a sandbox token. Leave it off until you've watched fixes and rollbacks work on sandbox hosts. |

Each host must also opt in locally (`--allow-remediation` at install). The server can't turn remediation on for a host.

## Alerts

| Variable | Default | What it does |
|---|---|---|
| `NIMSTEAD_SMTP_URL` | none | `smtp://user:pass@host:587` (STARTTLS) or `smtps://host:465`. Credentials are never sent without TLS. |
| `NIMSTEAD_OPEN_SIGNUP` | off | `1` = dev/test/demo only: sign-ups create accounts instantly, which tells anyone whether an email has an account. Off: the first account sets the server up, later sign-ups finish from an emailed link (SMTP needed; without it they're closed and staff join by SSO). |
| `NIMSTEAD_SMTP_FROM` | none | Sender address for alert email. Each recipient added in Settings first gets a confirmation email (fixed text, a link built from `NIMSTEAD_PUBLIC_URL`) and receives alerts only after confirming. |

Webhook and email recipients are set by an admin in **Settings**.

## Single sign-on

Set up in **Settings** by an org admin, not with environment variables. Register `<NIMSTEAD_PUBLIC_URL>/api/auth/sso/callback` at your identity provider. Each email domain must be proven with a DNS TXT record before it routes sign-ins.

| Variable | Default | What it does |
|---|---|---|
| `NIMSTEAD_DNS_SERVER` | system resolver | `host[:port]` used for domain and external-target TXT checks. |

## AI (optional)

| Variable | Default | What it does |
|---|---|---|
| `ANTHROPIC_API_KEY` | none | Turns on plain-English explanations and natural-language search. Nothing is sent to Anthropic without it. |
| `NIMSTEAD_AI` | on when a key is set | `0` turns the features off even with a key. |
| `NIMSTEAD_AI_MODEL` | `claude-opus-5-5` | Model used. |

## Development only

| Variable | What it does |
|---|---|
| `NIMSTEAD_ALLOW_PRIVATE_TARGETS=1` | Lets webhooks and the IdP live on a private network. Turns off SSRF protection for private addresses. Never in production. |
| `NIMSTEAD_WEB_DIST`, `NIMSTEAD_AGENT_FILE` | Override where the built UI and the served agent file are read from. |
