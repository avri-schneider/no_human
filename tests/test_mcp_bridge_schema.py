"""CTRL-53: the MCP task tools accept only their declared scalar inputs.

FastMCP builds each tool's JSON input schema from the function signature, so a
signature of typed scalars with no ``dict``/``**kwargs`` parameter means an
MCP/tracker-supplied payload has nowhere to bind an unexpected field. This
introspects the REAL registered tools and fails the day a signature grows a
dict param, ``**kwargs``, or a non-scalar annotation — i.e. the day the schema
would start accepting unknown structure.
"""
import inspect

from no_human.intake import mcp_bridge


def _underlying(tool):
    # @mcp.tool() may return the function itself or wrap it in a tool object;
    # reach the real function whichever it is.
    for attr in ("fn", "func", "__wrapped__"):
        f = getattr(tool, attr, None)
        if callable(f):
            return f
    return tool


def test_mcp_task_tools_take_only_declared_scalar_fields():
    expected = {
        "task_add": {"title": str, "description": str, "repo_path": str},
        "task_status": {"task_id_or_external_id": str},
    }
    for name, want in expected.items():
        fn = _underlying(getattr(mcp_bridge, name))
        sig = inspect.signature(fn)
        assert set(sig.parameters) == set(want), (name, list(sig.parameters))
        for p in sig.parameters.values():
            assert p.kind is not inspect.Parameter.VAR_KEYWORD, (name, "**kwargs")
            assert p.kind is not inspect.Parameter.VAR_POSITIONAL, (name, "*args")
            # Annotations may be stringized (`from __future__ import annotations`),
            # so accept the type or its name — but nothing else (a dict/Any param
            # would fail here).
            want_t = want[p.name]
            assert p.annotation in (want_t, want_t.__name__), (name, p.name, p.annotation)
