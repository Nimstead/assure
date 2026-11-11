"""The collection document a current agent (0.5.0+) sends with its inventory, for seeds and tests that post hand-written
inventories: every source read in full, its count what the inventory holds. Since phase 5 of tasks/plan-engine-findings.md an
inventory without one opens no findings (an agent too old to say what it read), so synthetic hosts must look like current agents.
"""

from nimstead.engine.collection import AGENT_APPS, DOC_VERSION, LINUX_SOURCES, WINDOWS_SOURCES, linux

WINDOWS_ROWS = {"windows_build": "Windows", "uninstall": "WinApp", "microsoft_products": "Microsoft", "drivers": "WinDriver"}


def document(inv: dict) -> dict:
    """The document for this inventory body (`ecosystem`, `packages`), as the agent would send it."""
    rows = inv.get("packages") or []

    def n(eco):
        return sum(1 for p in rows if p.get("ecosystem") == eco)
    if linux(inv.get("ecosystem") or ""):
        sources = {"os_release": {"state": "ok", "count": 1}, "package_db": {"state": "ok", "count": n(inv["ecosystem"])}}
        assert set(sources) == set(LINUX_SOURCES)
    else:
        sources = {s: {"state": "ok", "count": n(WINDOWS_ROWS[s]) if s in WINDOWS_ROWS else 1} for s in WINDOWS_SOURCES}
        sources["user_hives"]["count"] = 0  # per-user installs are counted in `uninstall`'s rows
    sources |= {src: {"state": "ok", "count": n(eco)} for src, eco, _ in AGENT_APPS}
    return {"v": DOC_VERSION, "sources": sources}


def with_document(inv: dict) -> dict:
    """The body with a document, unless it already says what it has (`"collection": None` is an old agent on purpose)."""
    return inv if "collection" in inv else {**inv, "collection": document(inv)}
