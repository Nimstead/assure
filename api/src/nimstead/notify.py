"""Failure alerts: webhook (Slack-compatible or generic JSON) and optional SMTP email, sent off the request path.

notify() reads the org's settings, hands delivery to a background thread and returns. Every attempt is
recorded in the notification table (ok/failed + error) so a dead webhook shows up in Settings.
"""

import json
import logging
import os
import smtplib
import ssl
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import sso
from nimstead.db import Asset, Notification, Org, now
from nimstead.netguard import check_public_url, guarded_client

log = logging.getLogger(__name__)
_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="notify")
_pending: set[Future] = set()
# Injectable for tests. None -> SSRF-guarded client with short timeouts.
http_client: httpx.Client | None = None


def smtp_configured() -> bool:
    return bool(os.environ.get("NIMSTEAD_SMTP_URL") and os.environ.get("NIMSTEAD_SMTP_FROM"))


def webhook_url(org: Org) -> str | None:
    """Sealed at rest; a URL saved before sealing existed is used as-is until seal_legacy() runs."""
    u = org.notify_webhook_url
    return sso.unseal(u) if u and u.startswith(("fernet:", "vault:")) else u


def seal_legacy(s: Session) -> int:
    """Seal webhook URLs stored in plaintext by older versions. Runs with the hourly feed update."""
    n = 0
    for org in s.scalars(select(Org).where(Org.notify_webhook_url.is_not(None))):
        if not org.notify_webhook_url.startswith(("fernet:", "vault:")):
            org.notify_webhook_url, n = sso.seal(org.notify_webhook_url), n + 1
    s.commit()
    return n


def recipients(org: Org) -> list[str]:
    """Only addresses whose owner confirmed: an admin can't make the server mail arbitrary people."""
    return [e for e in org.notify_emails if e in org.notify_emails_confirmed]


def confirm_token(org_id: str, email: str) -> str:
    return sso.domain_token(org_id, "notify-email:" + email)


def send_confirmation(bind, org_id: str, email: str, link: str) -> None:
    """Fixed text plus a link to this server: nothing the requesting admin wrote reaches the recipient."""
    text = ("confirm you want to receive security alerts\n\n"
            "This address was added to receive Nimstead security alerts. If you expected this, confirm here:\n"
            f"{link}\n\nIf you didn't, ignore this email: no alerts are sent until the address is confirmed.")
    _submit(bind, org_id, "email_confirmation", text, False, [("email", [email], "")], 1)


def send_signup_email(email: str, link: str | None, signin_url: str) -> None:
    """The second half of a sign-up, sent to the address itself: a link to finish, or (the address already has an account)
    a note saying so. Either way the person signing up sees the same response, so it can't be used to test addresses.
    No org exists yet, so failures are logged rather than recorded per org."""
    if link:
        text = ("finish creating your account\n\nSomeone, hopefully you, asked to create a Nimstead account with this address. "
                f"To finish, open this link within 24 hours:\n{link}\n\nIf it wasn't you, ignore this email: no account is created.")
    else:
        text = ("you already have an account\n\nSomeone tried to create a Nimstead account with this address, which already "
                f"has one. Sign in here instead:\n{signin_url}\n\nIf it wasn't you, nothing has changed.")

    def send():
        try:
            _send_email([email], "signup", text, False)
        except Exception as e:
            log.warning("sign-up email could not be sent: %s", type(e).__name__)
    f = _pool.submit(send)
    _pending.add(f)
    f.add_done_callback(_pending.discard)


def notify(s: Session, org_id: str, kind: str, text: str, urgent: bool = False) -> None:
    """Best-effort and non-blocking: never raises, never waits on the network. No config -> no-op."""
    try:
        org = s.get(Org, org_id)
        if not org:
            return
        targets = []
        if url := webhook_url(org):
            targets.append(("webhook", url, org.notify_webhook_format))
        if recipients(org) and smtp_configured():
            targets.append(("email", recipients(org), ""))
        if not targets:
            return
        # ponytail: in-process queue; failed attempts are persisted and retried by retry_failed() (hourly feed run)
        _submit(s.get_bind(), org_id, kind, text, urgent, targets, 1)
    except Exception:
        log.exception("could not queue notification")


def _submit(bind, org_id, kind, text, urgent, targets, attempt):
    f = _pool.submit(_deliver, bind, org_id, kind, text, urgent, targets, attempt)
    _pending.add(f)
    f.add_done_callback(_pending.discard)


MAX_ATTEMPTS, RETRY_WINDOW = 3, timedelta(hours=24)
SILENT_AFTER = timedelta(hours=14)  # two missed 6-hour reports plus timer jitter
SERVER_GAP = timedelta(hours=2)  # the feed run is hourly: a longer gap means the server, not the hosts, was down
GRACE = timedelta(hours=7)  # after such a gap, one 6-hour report cycle (plus jitter) for hosts to catch up


def _monitor_state() -> Path:
    from nimstead.app import RELEASE_DIR  # the server's data folder (/data/release in Docker)
    return RELEASE_DIR / "monitor.json"


def _in_server_grace(state_file: Path) -> bool:
    """Records this check; True while hosts are still catching up after the server itself was down."""
    try:
        st = json.loads(state_file.read_text())
        last, grace = datetime.fromisoformat(st["last_check"]), datetime.fromisoformat(st["grace_until"]) if st.get("grace_until") else None
    except (OSError, ValueError, KeyError, TypeError):
        last, grace = None, None
    if last and now() - last > SERVER_GAP:
        grace = now() + GRACE
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps({"last_check": now().isoformat(), "grace_until": grace.isoformat() if grace else None}))
    except OSError as e:
        log.warning("could not record the not-reporting check: %s", e)
    return bool(grace and now() < grace)


def alert_silent_hosts(s: Session, state_file: Path | None = None) -> int:
    """One alert per org per run, naming each host that has newly stopped reporting; the next inventory clears a host's
    marker. Held back for one report cycle after the server itself was down, so an outage doesn't page about every host.
    Returns the number of hosts newly flagged."""
    if _in_server_grace(state_file or _monitor_state()):
        return 0
    by_org: dict[str, list[Asset]] = {}
    for a in s.scalars(select(Asset).where(Asset.kind == "host", Asset.last_seen < now() - SILENT_AFTER, Asset.silent_alerted_at.is_(None))
                       .order_by(Asset.hostname)):
        by_org.setdefault(a.org_id, []).append(a)
    for org_id, hosts in by_org.items():
        names = ", ".join(f"{a.hostname} ({int((now() - a.last_seen).total_seconds() // 3600)} h)" for a in hosts[:20])
        more = f" and {len(hosts) - 20} more" if len(hosts) > 20 else ""
        notify(s, org_id, "host_not_reporting",
               f"{len(hosts)} machine{'s' * (len(hosts) > 1)} stopped reporting: {names}{more}. Their findings may be out of date: "
               "check each is running and the Nimstead agent's timer or scheduled task.")
        for a in hosts:
            a.silent_alerted_at = now()
    s.commit()
    return sum(len(h) for h in by_org.values())


def retry_failed(s: Session) -> int:
    """Re-send failed deliveries (up to MAX_ATTEMPTS within RETRY_WINDOW) to the org's current targets."""
    n = 0
    for row in s.scalars(select(Notification).where(Notification.ok.is_(False), Notification.retried.is_(False),
                                                    Notification.attempt < MAX_ATTEMPTS, Notification.ts > now() - RETRY_WINDOW)):
        org = s.get(Org, row.org_id)
        if row.channel == "webhook" and org.notify_webhook_url:
            target = [("webhook", webhook_url(org), org.notify_webhook_format)]
        elif row.channel == "email" and row.kind != "email_confirmation" and recipients(org) and smtp_configured():
            target = [("email", recipients(org), "")]
        else:
            continue
        row.retried = True
        _submit(s.get_bind(), row.org_id, row.kind, row.text, row.urgent, target, row.attempt + 1)
        n += 1
    s.commit()
    return n


def flush() -> None:
    """Wait for queued deliveries (tests, graceful shutdown)."""
    for f in list(_pending):
        f.result()


def _deliver(bind, org_id: str, kind: str, text: str, urgent: bool, targets: list, attempt: int = 1) -> None:
    results = []
    for channel, target, fmt in targets:
        try:
            if channel == "webhook":
                _send_webhook(target, fmt, kind, text, urgent)
            else:
                _send_email(target, kind, text, urgent)
            results.append((channel, True, None))
        except Exception as e:
            err = f"{type(e).__name__}: {e}".replace(str(target), "<webhook url>")[:500]  # Slack URLs are secrets: keep them out of logs/UI
            log.warning("notification via %s failed: %s", channel, err)
            results.append((channel, False, err))
    try:
        with Session(bind) as s:
            s.add_all(Notification(org_id=org_id, kind=kind, channel=c, urgent=urgent, ok=ok, error=err, text=text[:2000],
                                   attempt=attempt) for c, ok, err in results)
            s.commit()
    except Exception:
        log.exception("could not record notification attempt")


def _send_webhook(url: str, fmt: str, kind: str, text: str, urgent: bool) -> None:
    check_public_url(url)
    msg = f"URGENT: {text}" if urgent else text
    if fmt == "slack":  # agent-supplied text (hostnames, job errors) must not become links or @channel mentions
        msg = msg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    body = {"text": msg} if fmt == "slack" else {"kind": kind, "urgent": urgent, "text": msg, "source": "nimstead"}
    client = http_client or guarded_client()
    try:
        r = client.post(url, json=body)
        if r.is_error:
            raise RuntimeError(f"webhook returned HTTP {r.status_code}")
    finally:
        if http_client is None:
            client.close()


def _send_email(to: list[str], kind: str, text: str, urgent: bool) -> None:
    u = urlsplit(os.environ["NIMSTEAD_SMTP_URL"])  # smtp://user:pass@host:587 (STARTTLS if offered) or smtps://host:465
    m = EmailMessage()
    m["From"], m["To"] = os.environ["NIMSTEAD_SMTP_FROM"], ", ".join(to)
    m["Subject"] = ("[URGENT] " if urgent else "") + "Nimstead: " + text.splitlines()[0][:100]
    m.set_content(text)
    if u.scheme == "smtps":
        srv = smtplib.SMTP_SSL(u.hostname, u.port or 465, timeout=10, context=ssl.create_default_context())
    else:
        srv = smtplib.SMTP(u.hostname, u.port or 587, timeout=10)
    with srv:
        if u.scheme != "smtps":
            srv.ehlo()
            if srv.has_extn("starttls"):
                srv.starttls(context=ssl.create_default_context())
                srv.ehlo()
            elif u.username:  # a stripped STARTTLS offer must not make us send the password in clear
                raise smtplib.SMTPException("server offers no STARTTLS; refusing to send credentials unencrypted")
        if u.username:
            srv.login(u.username, u.password or "")
        srv.send_message(m)
