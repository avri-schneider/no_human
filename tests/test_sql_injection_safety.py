"""CTRL-44: tracker-derived fields are written with bound parameters.

A SQL-injection payload placed in a task title and a rule's content must be
stored as literal text and never executed. If any write concatenated the value
into the SQL string instead of binding it, the ``DROP TABLE`` below would fire
and the follow-up reads would raise "no such table". Parameterization is what
makes these payloads inert — this exercises it end to end through the real
Store, not by inspecting the source.
"""
import pytest

from no_human.core.db import Store
from no_human.core.task import Task

SQLI = "Robert'); DROP TABLE tasks; DROP TABLE memories;-- "


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
