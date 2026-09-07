"""CTRL-44: tracker-derived fields are written with bound parameters.

A SQL-injection payload placed in a task title and a rule's content must be
stored as literal text and never executed. If any write concatenated the value
into the SQL string instead of binding it, the ``DROP TABLE`` below would fire
and the follow-up reads would raise "no such table". Parameterization is what
makes these payloads inert — this exercises it end to end through the real
Store, not by inspecting the source.
"""
import pathlib
import re

import pytest

from no_human.core.db import Store
from no_human.core.task import Task

SQLI = "Robert'); DROP TABLE tasks; DROP TABLE memories;-- "

# An f-string / .format / %-interpolated execute() is how a tracker-derived
# value would be concatenated into SQL. The only interpolated execute() sites
# allowed are ones that inject NO external data — an internal column-name/type
# migration, or a run of generated '?' placeholders (values still bound). Any
# other shape is a prohibited string-concatenated write.
_EXECUTE_INTERP = re.compile(r"\.execute(?:many)?\(\s*(?:f[\"']|[\"'].*?[\"']\s*(?:%|\.format\())")
_SAFE_INTERP = (
    re.compile(r"ALTER TABLE \w+ ADD COLUMN"),     # internal DDL over a column table
    re.compile(r"IN \(\{[A-Za-z_]*placeholder"),   # generated '?' placeholders, values bound
)


def test_no_string_concatenated_sql_in_the_tree():
    """CTRL-44: string-concatenated SQL is prohibited repo-wide. This guard
    fails the build if a NEW interpolated execute() appears that is not one of
    the two known-safe internal shapes — i.e. the shape that would splice a
    tracker-derived value into a query. Content-matched, so line drift can't
    weaken it."""
    root = pathlib.Path(__file__).resolve().parent.parent / "src" / "no_human"
    offenders = []
    for py in root.rglob("*.py"):
        for lineno, line in enumerate(py.read_text().splitlines(), 1):
            if _EXECUTE_INTERP.search(line) and not any(p.search(line) for p in _SAFE_INTERP):
                offenders.append(f"{py.relative_to(root.parent.parent).as_posix()}:{lineno}: {line.strip()}")
    assert not offenders, "string-concatenated SQL found:\n" + "\n".join(offenders)


@pytest.mark.asyncio
async def test_tracker_sql_injection_payloads_are_stored_as_literal_text(tmp_path):
    store = await Store(tmp_path / "sqli.db").connect()
    try:
        # Tracker-derived task field: the title is an injection payload.
        task = Task.new(SQLI, repo_path="/tmp/r")
        task.acceptance_criteria = ["n/a"]
        await store.create_task(task)
        got = await store.get_task(task.id)
        assert got is not None and got.title == SQLI  # verbatim, not executed

        # A rule (the tracker-derived prompt-injection chokepoint) with the
        # payload in both title and content.
        mem_id = await store.add_memory(
            mem_type="rule", title=SQLI, content=SQLI, confirmed=True,
        )
        assert mem_id is not None
        rules = await store.list_memories(confirmed=True)
        assert any(m["content"] == SQLI for m in rules), "rule content was altered"

        # The tables survived: a concatenated DROP would have destroyed them,
        # making these reads raise. That they still answer proves the writes
        # bound their parameters.
        assert await store.get_task(task.id) is not None
        assert isinstance(await store.list_tasks(), list)
    finally:
        await store.close()
