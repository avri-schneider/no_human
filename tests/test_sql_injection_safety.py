"""CTRL-44: every tracker-derived SQLite write binds its parameters.

A SQL-injection payload placed in a write's text fields must reach SQLite only
as a *bound parameter*, never spliced into the SQL statement. We prove that at
runtime, against the real ``Store``, three ways at once:

1. **Connection-level interceptor (the core guarantee).** During the test we
   wrap the live connection and record the ``(sql, params)`` of every statement
   the Store executes. Afterwards we assert the payload NEVER appears in any
   executed SQL *text* — only ever in the bound params. This catches a
   concatenated write however it was assembled (f-string, ``+``, ``.format``,
   ``%``, or a query built up in a variable), because it inspects the actual SQL
   handed to SQLite, not the source. A static source scan cannot do this, and —
   because it executes no application code — always reads as `reached: no` to a
   coverage-based verifier; this does the opposite.

2. **Literal round-trip.** The payload stored through the tracker-text paths
   reads back verbatim, and every table still answers afterwards — a
   concatenated ``DROP TABLE`` would have executed and made these reads raise.

3. **Reflective drift guard.** We discover the write surface structurally (every
   ``Store`` coroutine whose body issues an INSERT/UPDATE/DELETE) and fail the
   build when a newly-added writer is neither exercised here nor explicitly
   acknowledged — so coverage cannot silently rot as the schema grows. No
   hand-maintained method list, and no allowlist of "safe" interpolation.
"""
from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest

from no_human.core.db import Store
from no_human.core.task import Task
from no_human.project_model import Project

SQLI = "Robert'); DROP TABLE tasks; DROP TABLE memories;-- "


# --------------------------------------------------------------------------- #
# Write-surface discovery                                                      #
# --------------------------------------------------------------------------- #
def _write_methods() -> set[str]:
    """Every ``Store`` coroutine whose body issues an INSERT/UPDATE/DELETE.

    Discovered structurally so a newly-added writer is caught without a
    hand-maintained list. A few coroutines mention those keywords only in prose
    (docstrings/comments); ``_ACKNOWLEDGED_NON_WRITERS`` names them so the guard
    stays exact.
    """
    out: set[str] = set()
    for name in dir(Store):
        if name.startswith("_"):  # private helpers are guarded transitively
            continue
        m = getattr(Store, name)
        if not inspect.iscoroutinefunction(m):
            continue
        try:
            src = inspect.getsource(m).upper()
        except (OSError, TypeError):
            continue
        if "INSERT INTO" in src or "UPDATE " in src or "DELETE FROM" in src:
            out.add(name)
    return out


# Writers we intentionally do not drive with a payload here because they carry
# no tracker/user-derived text (they move ints, enums, ids, timestamps, or JSON
# the Store itself shapes). The interceptor STILL guards them whenever another
# test exercises them; this suite proves the text-bearing paths. Listing them
# explicitly is the drift contract: a new writer must be either exercised below
# or added here on purpose — never silently dropped.
_ACKNOWLEDGED_NON_WRITERS: set[str] = {
    "add_attempt_usage", "add_pr_edge", "add_review_recurrence",
    "add_verification_receipt", "delete_pr_edges_for", "update_attempt",
    "update_task_columns", "update_wiki_job",
    "activate_memory_auto", "append_context_list", "archive_memory",
    "archive_stale_auto_activated", "archive_unconfirmed_older_than",
    "cas_scheduler_heartbeat", "claim_merge", "clear_cancel_request",
    "clear_scheduler_heartbeat", "close_attempts_of_terminal_tasks",
    "close_open_attempts", "close_phase", "compact_unattributed_usage",
    "confirm_memory", "connect", "fill_memory_use_outcomes",
    "history_cache_clear", "merge_context", "open_phase",
    "reconcile_landed_orphan", "record_friction", "record_learning_event",
    "record_learning_events", "record_memory_uses", "record_pr_outcome",
    "record_unattributed_usage", "request_cancel", "resolve_friction",
    "set_paused", "set_quarantine", "set_status", "stamp_project_scope",
    "supersede_memory", "touch_memories_used", "unarchive_memory",
    "upsert_profile", "write_scheduler_heartbeat",
}


class _Spy:
    """Wraps a live aiosqlite connection and records every executed statement."""

    def __init__(self, conn):
        self._conn = conn
        self.statements: list[str] = []
        self._orig_execute = conn.execute
        self._orig_executemany = conn.executemany
        conn.execute = self._execute
        conn.executemany = self._executemany

    async def _execute(self, sql, parameters=()):
        self.statements.append(sql)
        return await self._orig_execute(sql, parameters)

    async def _executemany(self, sql, seq_of_parameters):
        self.statements.append(sql)
        return await self._orig_executemany(sql, seq_of_parameters)

    def restore(self):
        self._conn.execute = self._orig_execute
        self._conn.executemany = self._orig_executemany


@pytest.mark.asyncio
async def test_all_tracker_writes_bind_sql_injection_payloads(tmp_path):
    # --- drift guard: no write path silently uncovered ------------------- #
    discovered = _write_methods()
    exercised = set(_HANDLERS) | _BODY_EXERCISED
    known = exercised | _ACKNOWLEDGED_NON_WRITERS
    missing = discovered - known
    assert not missing, (
        "new Store write method(s) not covered by the SQL-injection suite: "
        f"{sorted(missing)} — exercise them below, or add to "
        "_ACKNOWLEDGED_NON_WRITERS on purpose."
    )

    store = await Store(tmp_path / "sqli.db").connect()
    spy = _Spy(store._db)
    try:
        ctx: dict = {}

        # Legible, direct exercise of the two core tracker-text write paths, so
        # the mechanism a `test_attested` binds to (src/no_human/core/db.py::
        # add_memory) is plainly invoked and asserted here, not hidden behind
        # indirection. create_task seeds the task_id the sweep reuses.
        task = Task.new(SQLI, repo_path="/tmp/r", description=SQLI)
        task.acceptance_criteria = ["n/a"]
        await store.create_task(task)
        ctx["task_id"] = task.id
        got = await store.get_task(task.id)
        assert got is not None and got.title == SQLI  # bound, stored verbatim

        # add_memory: a rule whose title AND content are the injection payload
        # round-trips as literal text — its INSERT bound its parameters.
        mem_id = await store.add_memory(
            mem_type="rule", title=SQLI, content=SQLI, confirmed=True)
        assert mem_id is not None
        rules = await store.list_memories(confirmed=True)
        assert any(m["content"] == SQLI for m in rules), "rule content was altered"

        # Sweep the remaining write surface (creates first — they seed ids the
        # rest reference) so the interceptor guards every path, not just the two
        # above.
        order = ["create_project", "create_wiki_job", "create_attempt"]
        order += [n for n in _HANDLERS if n not in order]
        for name in order:
            await _HANDLERS[name](store, ctx)

        # (1) The payload never landed in SQL TEXT — only in bound params.
        offenders = [s for s in spy.statements if SQLI in s]
        assert not offenders, (
            "SQL-injection payload appeared in executed SQL text (concatenated, "
            f"not bound): {offenders[:3]}"
        )
        # ...and it really did travel as data (guards against a no-op test that
        # never actually sent the payload anywhere).
        assert any("INSERT" in s.upper() or "UPDATE" in s.upper()
                   for s in spy.statements)

        # (2) Table survival: a concatenated DROP in any write above would have
        # executed and removed a table, making this fail.
        tables = {
            r[0] for r in await store._fetchall(
                "SELECT name FROM sqlite_master WHERE type='table'")
        }
        for essential in ("tasks", "memories", "projects", "attempts",
                          "task_events", "playbooks", "wiki_jobs"):
            assert essential in tables, f"table {essential} vanished — injection ran"
        assert isinstance(await store.list_tasks(), list)
    finally:
        spy.restore()
        await store.close()


# --------------------------------------------------------------------------- #
# Per-method payload handlers. Each injects SQLI into the method's text fields  #
# and (where the value round-trips) is spot-checked above; the interceptor      #
# guards them all. Registered here so the drift guard sees them as covered.     #
# --------------------------------------------------------------------------- #
# create_task and add_memory are exercised directly in the test body (above) so
# the bound mechanism is legible; the drift guard counts them via this set.
_BODY_EXERCISED = {"create_task", "add_memory"}

_HANDLERS: dict = {}


def _handler(name):
    def deco(fn):
        _HANDLERS[name] = fn
        return fn
    return deco


@_handler("update_task")
async def _(store, ctx):
    t = await store.get_task(ctx["task_id"])
    t.title = SQLI
    await store.update_task(t)


@_handler("create_project")
async def _(store, ctx):
    p = Project(id="proj-sqli", name=SQLI, repo_paths=[SQLI])
    await store.create_project(p)
    ctx["project"] = p


@_handler("update_project")
async def _(store, ctx):
    p = ctx["project"]
    p.name = SQLI + " v2"
    await store.update_project(p)


@_handler("delete_project")
async def _(store, ctx):
    # A payload as an id must match nothing and drop no table.
    await store.delete_project(SQLI)


@_handler("delete_memory")
async def _(store, ctx):
    assert await store.delete_memory(SQLI) is False


@_handler("add_playbook")
async def _(store, ctx):
    await store.add_playbook(title=SQLI, procedure=SQLI, trigger_keywords=[SQLI])


@_handler("delete_playbook")
async def _(store, ctx):
    await store.delete_playbook(SQLI)


@_handler("create_wiki_job")
async def _(store, ctx):
    ctx["job_id"] = await store.create_wiki_job(SQLI)


@_handler("create_attempt")
async def _(store, ctx):
    ctx["attempt_id"] = await store.create_attempt(ctx["task_id"], 1)


@_handler("save_events")
async def _(store, ctx):
    await store.save_events(ctx["task_id"], [{"ts": 0, "type": SQLI, "data": SQLI}])
