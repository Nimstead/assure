"""Benchmark references on a real install, in a DISPOSABLE Windows VM (sandbox/winvm.py; DECISIONS 75, 76).

20 sampled automated rules: what the agent reported and how the server judged it, beside the same setting read another way in
the guest, written out so a person can check them by hand. Also says whether values reached the server whole and how many rules
read "not assessed" for lack of a value, which should be none on a host where the agent runs as SYSTEM.

Run from api/:  uv run python ../sandbox/winbaseline.py VM_NAME [--keep]   Writes sandbox/last_run_winbaseline.json.
"""

import json
import random
import sys

import wine2e as h  # noqa: E402  (reads VM_NAME from argv)
import winfixes as f
import winproducts as wp

from nimstead import winbaseline  # noqa: E402

# --judge-as="Windows 11": a host with no baseline of its own (a German Windows 10, for W19) read against one, to check that audit
# policy and user rights arrive whole on a localised install; its pass/fail then says nothing about that OS
JUDGE_AS = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--judge-as=")), None)
OUT = f.ROOT / "sandbox" / ("last_run_winbaseline_judged_as.json" if JUDGE_AS else "last_run_winbaseline.json")
SAMPLE = 20


def guest_reading(rule):
    """The same setting, not through the agent's script: Get-ItemProperty, auditpol's table, secedit's file."""
    if "reg" in rule:
        key, name = rule["reg"]
        return h.guest(f"(Get-ItemProperty -LiteralPath 'Registry::HKLM\\{key}' -Name '{name}' -ErrorAction SilentlyContinue).'{name}'", check=False).strip() or "not set"
    if "audit" in rule:
        return h.guest(f"auditpol /get /subcategory:'{rule['audit']}' /r", check=False).strip().splitlines()[-1]
    return h.guest(rf"secedit /export /areas USER_RIGHTS /cfg C:\nimtest\ur.inf /quiet | Out-Null; (Select-String -Path C:\nimtest\ur.inf -Pattern '^{rule['right']}\b').Line", check=False).strip() or "nobody"


def main(keep=False) -> int:
    h.winvm.wait_ready(h.NAME, minutes=90)
    h.guest(r"New-Item -ItemType Directory -Force C:\nimtest, C:\ProgramData\Nimstead | Out-Null")
    f.runtime()
    f.copy_in(f.ROOT / "agent" / "nimstead_agent.py")
    inv = wp.collect()
    facts = inv.get("facts") or {}
    result = winbaseline.evaluate(f"{JUDGE_AS} (judged as, really {inv.get('os_name')})" if JUDGE_AS else inv.get("os_name"), facts)
    h.note("agent report", os_name=inv.get("os_name"), domain_role=facts.get("domain_role"), installation_type=facts.get("installation_type"),
           report_bytes=len(json.dumps(facts)), baseline_bytes=len(json.dumps(facts.get("baseline"))))
    checks = {"this OS has a baseline": result is not None, "the agent reported baseline values": bool(facts.get("baseline")),
              "the report fits the server's limit": len(json.dumps(facts)) <= 64_000}
    if result:
        counts = {k: result[k] for k in ("name", "version", "automated", "manual", "pass", "fail", "not_assessed", "not_applicable")}
        h.note("result", **counts)
        rules = {r["id"]: r for r in next(b for b in winbaseline.baselines() if b["id"] == result["baseline_id"])["rules"]}
        judged = [r for r in result["rules"] if r["status"] != winbaseline.NOT_APPLICABLE]
        for row in random.Random(75).sample(judged, min(SAMPLE, len(judged))):  # noqa: S311  (fixed seed: the same rules on every rerun)
            h.note(f"rule {row['id']}", status=row["status"], expected=row["expected"], agent_read=row["found"], guest_read=guest_reading(rules[row["id"]]))
        h.note("CHECK BY HAND: each rule's status against guest_read above; a mismatch is a bug in the table or the collector")
    ok = all(checks.values())
    h.note("RESULT: " + ("PASS (automatic checks only, the 20 rules still need reading)" if ok else "FAIL"), checks=checks)
    if not keep:
        h.winvm.destroy(h.NAME)
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        rc = main(keep="--keep" in sys.argv)
    except Exception as e:
        h.note("RESULT: FAIL", error=f"{type(e).__name__}: {e}"[:3000])
        rc = 1
    OUT.write_text(json.dumps(h.log, indent=2, default=str))
    sys.exit(rc)
