"""Failure alerts: webhook (Slack-compatible or generic JSON) and optional SMTP email, sent off the request path.

notify() reads the org's settings, hands delivery to a background thread and returns. Every attempt is
recorded in the notification table (ok/failed + error) so a dead webhook shows up in Settings.
"""

import logging
import os
import smtplib
import ssl
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import timedelta
from email.message import EmailMessage
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead.db import Notification, Org, now
from nimstead.netguard import check_public_url, guarded_client

log = logging.getLogger(__name__)
_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="notify")
_pending: set[Future] = set()
# Injectable for tests. None -> SSRF-guarded client with short timeouts.
http_client: httpx.Client | None = None


def smtp_configured() -> bool:
    return bool(os.environ.get("NIMSTEAD_SMTP_URL") and os.environ.get("NIMSTEAD_SMTP_FROM"))


def notify(s: Session, org_id: str, kind: str, text: str, urgent: bool = False) -> None:
    """Best-effort and non-blocking: never raises, never waits on the network. No config -> no-op."""
    try:
        org = s.get(Org, org_id)
        if not org:
            return
        targets = []
        if org.notify_webhook_url:
            targets.append(("webhook", org.notify_webhook_url, org.notify_webhook_format))
        if org.notify_emails and smtp_configured():
            targets.append(("email", list(org.notify_emails), ""))
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


def retry_failed(s: Session) -> int:
    """Re-send failed deliveries (up to MAX_ATTEMPTS within RETRY_WINDOW) to the org's current targets."""
    n = 0
    for row in s.scalars(select(Notification).where(Notification.ok.is_(False), Notification.retried.is_(False),
                                                    Notification.attempt < MAX_ATTEMPTS, Notification.ts > now() - RETRY_WINDOW)):
        org = s.get(Org, row.org_id)
        if row.channel == "webhook" and org.notify_webhook_url:
            target = [("webhook", org.notify_webhook_url, org.notify_webhook_format)]
        elif row.channel == "email" and org.notify_emails and smtp_configured():
            target = [("email", list(org.notify_emails), "")]
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
        if u.username:
            srv.login(u.username, u.password or "")
        srv.send_message(m)
