"""The home page's open-findings count by priority is answered from an index alone (0.14.1): at 297k open findings it read
every finding row (248 ms of a 0.40 s page); from the covering index (org_id, status, priority) it takes 33 ms."""

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.engine import Engine
from test_api import user


def test_the_home_pages_priority_count_reads_only_an_index(env):
    c = user(env)
    seen = []

    def capture(conn, cursor, statement, params, context, many):
        if "GROUP BY finding.priority" in statement:
            seen.append((statement, params))

    event.listen(Engine, "before_cursor_execute", capture)
    try:
        assert c.get("/api/summary").status_code == 200
    finally:
        event.remove(Engine, "before_cursor_execute", capture)
    assert seen, "the summary counts open findings by priority"
    engine = create_engine(env)
    indexes = {i["name"]: i["column_names"] for i in inspect(engine).get_indexes("finding")}
    assert indexes.get("ix_finding_open_priority") == ["org_id", "status", "priority"]
    if env.startswith("sqlite"):  # PostgreSQL scans a test-sized table whatever its indexes; SQLite's plan shows the index is enough
        statement, params = seen[0]
        with engine.connect() as conn:
            plan = " ".join(row[-1] for row in conn.exec_driver_sql("EXPLAIN QUERY PLAN " + statement, params))
        assert "COVERING INDEX ix_finding_open_priority" in plan, plan
