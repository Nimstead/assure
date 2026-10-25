import io
import json
import zipfile
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import sessionmaker
from test_api import INV, enrol, user

from nimstead import evidence
from nimstead.db import Finding, LedgerEntry, make_engine, now
from nimstead.verify_pack import verify


def setup_flow(env):
    c = user(env)
    a = enrol(c)
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    c.post("/api/agent/inventory", json=INV, headers=h)
    upgraded = {**INV, "packages": INV["packages"][:2] + [{"ecosystem": "PyPI", "name": "requests", "version": "2.32.4"}]}
    c.post("/api/agent/inventory", json=upgraded, headers=h)
    return c, a


def test_ledger_records_lifecycle_and_chain_is_valid(env):
    c, _ = setup_flow(env)
    led = c.get("/api/evidence/ledger").json()
    kinds = [e["kind"] for e in led["entries"]]
    assert led["problems"] == []
    assert kinds.count("inventory_received") == 2
    assert "finding_opened" in kinds and "finding_resolved" in kinds


def test_tampering_is_detected_and_pack_signing_refused(env, tmp_path, monkeypatch):
    monkeypatch.setattr(evidence, "KEY_FILE", tmp_path / "k.pem")
    c, _ = setup_flow(env)
    s = sessionmaker(make_engine(env))()
    s.execute(update(LedgerEntry).where(LedgerEntry.seq == 3).values(data={"vuln_id": "rewritten history"}))
    s.commit()
    assert any("hash mismatch" in p for p in c.get("/api/evidence/ledger").json()["problems"])
    assert c.get("/api/evidence/pack").status_code == 409

    s.execute(update(LedgerEntry).where(LedgerEntry.seq == 3).values(data={}))  # still wrong
    s.commit()
    assert c.get("/api/evidence/pack").status_code == 409


def test_pack_verifies_offline_and_detects_edits(env, tmp_path, monkeypatch):
    monkeypatch.setattr(evidence, "KEY_FILE", tmp_path / "k.pem")
    c, _ = setup_flow(env)
    r = c.get("/api/evidence/pack")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert {"pack.json", "pack.sig", "public_key.pem", "verify.py", "README.txt"} <= set(z.namelist())
    body, sig, key = z.read("pack.json"), z.read("pack.sig").decode(), z.read("public_key.pem")
    fp = c.get("/api/evidence/public-key").json()["fingerprint_sha256"]
    assert verify(body, sig, key, fp) == []
    assert any("no trusted key" in p for p in verify(body, sig, key))  # fingerprint is mandatory
    assert fp in z.read("README.txt").decode()

    pack = json.loads(body)
    assert pack["metrics"]["resolved"] >= 1
    assert {c["framework"] for c in pack["controls"]} >= {"UK Cyber Essentials", "ISO/IEC 27001:2022", "PCI DSS v4.0.1"}

    forged = body.replace(b'"organisation":"Acme"', b'"organisation":"Acmf"')
    assert forged != body
    assert "signature does not match pack contents or key" in verify(forged, sig, key, fp)

    # a forger re-signs the edited pack with their own key and swaps public_key.pem: caught by the pinned fingerprint
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    their_pem = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert verify(forged, base64.b64encode(k.sign(forged)).decode(), their_pem, fp) == [
        "public key is not the trusted Nimstead key (fingerprint mismatch)"]

    pack["ledger"]["entries"].pop(1)  # drop an entry, keep signature
    problems = verify(json.dumps(pack).encode(), sig, key, fp)
    assert any("chain broken" in p for p in problems)


def test_sla_metrics(env):
    c, _ = setup_flow(env)
    s = sessionmaker(make_engine(env))()
    org_id = s.scalar(select(Finding.org_id))
    # evaluate 200 days from now: every open finding is past its SLA
    pack = evidence.build_pack(s, org_id, now() - timedelta(days=365), now() + timedelta(days=200))
    m = pack["metrics"]
    assert m["overdue_open"] == s.query(Finding).filter_by(status="open").count() > 0
    statuses = {(x["framework"], x["control"]): x["status"] for x in pack["controls"]}
    assert statuses[("NIST SP 800-53 Rev. 5", "SI-2")] == "not_met"
    assert statuses[("NIST SP 800-53 Rev. 5", "RA-5")] == "met"


def test_risk_acceptance_is_recorded_and_expires(env):
    c, a = setup_flow(env)
    fid = c.get("/api/findings").json()[0]["id"]
    assert c.post(f"/api/findings/{fid}/accept", json={"reason": "short"}).status_code == 422
    r = c.post(f"/api/findings/{fid}/accept", json={"reason": "Compensating WAF rule in place, ticket SEC-12", "days": 30})
    assert r.json()["status"] == "accepted"
    assert c.get("/api/evidence/ledger").json()["entries"][0]["kind"] == "finding_accepted"

    s = sessionmaker(make_engine(env))()
    s.execute(update(Finding).where(Finding.id == fid).values(accepted_until=now() - timedelta(days=1)))
    s.commit()
    c.post("/api/agent/inventory", json=INV, headers={"Authorization": f"Bearer {a['agent_key']}"})
    assert c.get(f"/api/findings/{fid}").json()["status"] == "open"
    kinds = [e["kind"] for e in c.get("/api/evidence/ledger").json()["entries"]]
    assert "acceptance_expired" in kinds


def test_editing_findings_table_cannot_change_evidence(env):
    c, _ = setup_flow(env)
    s = sessionmaker(make_engine(env))()
    org_id = s.scalar(select(Finding.org_id))
    period = (now() - timedelta(days=365), now() + timedelta(days=200))
    before = evidence.build_pack(s, org_id, *period)["metrics"]
    assert before["overdue_open"] > 0
    # DB-level attacker makes everything look freshly detected and quickly fixed
    s.execute(update(Finding).values(first_seen=now() + timedelta(days=199), resolved_at=now() + timedelta(days=199)))
    s.commit()
    after = evidence.build_pack(s, org_id, *period)["metrics"]
    assert after["overdue_open"] == before["overdue_open"] and after["mttr_days"] == before["mttr_days"]


def test_pack_pins_whole_chain_head(env, tmp_path, monkeypatch):
    c, _ = setup_flow(env)
    s = sessionmaker(make_engine(env))()
    org_id = s.scalar(select(Finding.org_id))
    pack = evidence.build_pack(s, org_id, *evidence.default_period(30))
    last = s.scalar(select(LedgerEntry).order_by(LedgerEntry.seq.desc()).limit(1))
    assert pack["ledger"]["chain_head"] == {"seq": last.seq, "hash": last.hash}
