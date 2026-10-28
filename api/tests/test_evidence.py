import hashlib
import io
import json
import zipfile
from datetime import timedelta

from fastapi.testclient import TestClient
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
    assert {"pack.json", "pack.sig", "public_key.pem", "README.txt"} == set(z.namelist())
    assert "verify.py" not in z.namelist()  # the checker can't come inside what it checks: a forger would swap it
    body, sig, key = z.read("pack.json"), z.read("pack.sig").decode(), z.read("public_key.pem")
    fp = c.get("/api/evidence/public-key").json()["fingerprint_sha256"]
    assert verify(body, sig, key, fp) == []
    assert any("no trusted key" in p for p in verify(body, sig, key))  # fingerprint is mandatory
    assert fp in z.read("README.txt").decode()
    pk = c.get("/api/evidence/public-key").json()  # the verifier is published by the server, pinned by hash beside the key
    script = TestClient(c.app).get("/api/evidence/verify.py")
    assert script.status_code == 200 and hashlib.sha256(script.content).hexdigest() == pk["verifier_sha256"]

    pack = json.loads(body)
    assert pack["metrics"]["resolved"] >= 1
    # one key signs every tenant's packs and org names are free text: the signed body says who the tenant provably is
    assert pack["organisation_id"] and pack["organisation_created"] and pack["verified_domains"] == []
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
    forged_problems = verify(forged, base64.b64encode(k.sign(forged)).decode(), their_pem, fp)
    assert "public key is not the trusted Nimstead key (fingerprint mismatch)" in forged_problems
    assert "signature does not match pack contents or key" not in forged_problems  # the forgery itself is self-consistent

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


def test_no_activity_is_not_reported_as_met(env, tmp_path, monkeypatch):
    monkeypatch.setattr(evidence, "KEY_FILE", tmp_path / "k.pem")
    c, _ = setup_flow(env)
    s = sessionmaker(make_engine(env))()
    org_id = s.scalar(select(Finding.org_id))
    # A window after the setup's own fix: nothing fixed or changed in it, nothing overdue yet.
    start = now() + timedelta(minutes=1)
    pack = evidence.build_pack(s, org_id, start, start + timedelta(minutes=1))
    statuses = {(x["framework"], x["control"]): x["status"] for x in pack["controls"]}
    for key in (("UK Cyber Essentials", "Security update management"), ("NIST SP 800-53 Rev. 5", "SI-2"),
                ("CIS Controls v8.1", "7.3 / 7.4"), ("SOC 2 (TSC 2017)", "CC8.1")):
        assert statuses[key] == "no_activity", key
    for key in (("NIST SP 800-53 Rev. 5", "RA-5"), ("ISO/IEC 27001:2022", "A.8.8"), ("SOC 2 (TSC 2017)", "CC7.1"), ("NIS2 Directive", "Art. 21(2)(e)")):
        assert statuses[key] in ("met", "not_met"), key  # monitoring controls make a real claim either way
    assert statuses[("PCI DSS v4.0.1", "6.3.3")] == "met"  # "0 critical open > 30 days" is true with no fixes
    # Overdue findings always win: the same controls fail rather than read "no activity".
    late = evidence.build_pack(s, org_id, start, now() + timedelta(days=200))
    assert {(x["framework"], x["control"]): x["status"] for x in late["controls"]}[("NIST SP 800-53 Rev. 5", "SI-2")] == "not_met"
    # A pack carrying the new status still signs and verifies with the published verifier.
    z = zipfile.ZipFile(io.BytesIO(evidence.pack_zip(pack)))
    body, sig, key = z.read("pack.json"), z.read("pack.sig").decode(), z.read("public_key.pem")
    assert b'"no_activity"' in body
    assert verify(body, sig, key, c.get("/api/evidence/public-key").json()["fingerprint_sha256"]) == []


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


def _rewrite_chain_consistently(s, org_id, from_seq):
    """What a DB-level attacker can do: alter an entry and re-hash everything after it."""
    from nimstead.verify_pack import entry_hash
    rows = s.scalars(select(LedgerEntry).where(LedgerEntry.org_id == org_id).order_by(LedgerEntry.seq)).all()
    prev = None
    for e in rows:
        if e.seq >= from_seq:
            if e.seq == from_seq:
                e.data = {**e.data, "vuln_id": "nothing to see"}
            e.prev_hash = prev
            e.hash = entry_hash(evidence.entry_dict(e))
        prev = e.hash
    s.commit()


def test_without_checkpoint_consistent_rewrite_is_invisible(env):
    setup_flow(env)
    s = sessionmaker(make_engine(env))()
    org_id = s.scalar(select(Finding.org_id))
    _rewrite_chain_consistently(s, org_id, 3)
    assert evidence.verify_chain(s, org_id) == []  # documents why checkpoints exist


def test_checkpoint_detects_rewrite(env):
    c, _ = setup_flow(env)
    s = sessionmaker(make_engine(env))()
    org_id = s.scalar(select(Finding.org_id))
    cp = evidence.checkpoint(s, org_id)
    assert evidence.checkpoint(s, org_id) == cp  # idempotent while head unchanged
    _rewrite_chain_consistently(s, org_id, 3)
    assert any("ledger rewritten" in p for p in evidence.verify_chain(s, org_id))
    assert c.get("/api/evidence/pack").status_code == 409


def test_checkpoint_detects_truncation(env):
    from sqlalchemy import delete
    c, _ = setup_flow(env)
    s = sessionmaker(make_engine(env))()
    org_id = s.scalar(select(Finding.org_id))
    cp = evidence.checkpoint(s, org_id)
    s.execute(delete(LedgerEntry).where(LedgerEntry.seq >= cp["seq"] - 1))
    s.commit()
    assert any("truncated" in p for p in evidence.verify_chain(s, org_id))


def test_pack_carries_checkpoints_and_verifier_checks_them(env):
    c, _ = setup_flow(env)
    r = c.get("/api/evidence/pack")  # takes a checkpoint first
    z = zipfile.ZipFile(io.BytesIO(r.content))
    body, sig, key = z.read("pack.json"), z.read("pack.sig").decode(), z.read("public_key.pem")
    fp = c.get("/api/evidence/public-key").json()["fingerprint_sha256"]
    pack = json.loads(body)
    assert pack["ledger"]["checkpoints"] and verify(body, sig, key, fp) == []
    cp = pack["ledger"]["checkpoints"][-1]
    entry = next(e for e in pack["ledger"]["entries"] if e["seq"] == cp["seq"])
    entry["hash"] = "0" * 64
    assert any("checkpoint" in p for p in verify(json.dumps(pack).encode(), sig, key, fp))


def test_control_evidence_is_plain_text():
    """No Python reprs (dicts, None) leak into what auditors read."""
    from collections import defaultdict

    from nimstead import evidence
    m = defaultdict(int, mttr_days=None)
    for c in evidence._controls(m, evidence.SLA_DAYS):
        assert "None" not in c["evidence"] and "{" not in c["evidence"], c


def test_org_sla_and_new_framework_mappings_are_in_the_pack(env):
    from test_api import INV, enrol, user
    c = user(env)
    a = enrol(c)
    assert c.patch("/api/settings", json={"sla_days": {"fix-now": 7, "next": 21}}).status_code == 200  # in force before detection
    assert c.get("/api/settings").json()["sla_days"] == {"fix-now": 7, "next": 21, "planned": 90, "low": 180}
    c.post("/api/agent/inventory", json=INV, headers={"Authorization": f"Bearer {a['agent_key']}"})
    pack = c.get("/api/evidence/report").json()
    assert pack["sla_days"]["fix-now"] == 7 and {r["sla_days"] for r in pack["findings"] if r["priority"] == "fix-now"} == {7}
    c.patch("/api/settings", json={"sla_days": {"fix-now": 365}})  # relaxed after detection: those findings keep 7
    pack = c.get("/api/evidence/report").json()
    assert pack["sla_days"]["fix-now"] == 365 and {r["sla_days"] for r in pack["findings"] if r["priority"] == "fix-now"} == {7}
    controls = {(x["framework"], x["control"]): x for x in pack["controls"]}
    assert {("SOC 2 (TSC 2017)", "CC7.1"), ("SOC 2 (TSC 2017)", "CC8.1"), ("NIS2 Directive", "Art. 21(2)(e)")} <= set(controls)
    si2 = controls[("NIST SP 800-53 Rev. 5", "SI-2")]["evidence"]
    assert "in force when each was detected" in si2 and "fix-now 365 days" in si2 and "changed 2 times" in si2
    assert "not the vendor's release date" in controls[("PCI DSS v4.0.1", "6.3.3")]["evidence"]
    for bad in ({"fix-now": 0}, {"fix-now": 400}, {"urgent": 5}):
        assert c.patch("/api/settings", json={"sla_days": bad}).status_code == 422
