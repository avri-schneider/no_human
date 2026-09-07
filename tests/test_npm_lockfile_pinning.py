"""CTRL-48: CI/release npm installs are lockfile-pinned.

`npm ci` installs the exact dependency graph recorded in the committed
``package-lock.json`` and *fails* when the lockfile is missing or drifts from
``package.json`` — that failure is the enforcement. Bare ``npm install`` does
the opposite: it silently resolves (and can rewrite) the lockfile, so a build
using it can ship a dependency graph nobody committed. This guard scans every
workflow's ``run:`` steps and fails the build if a project install uses
``npm install`` instead of ``npm ci``. It is content-matched, so it catches a
regression the day someone adds an unpinned install — which is what makes the
pinning *enforced* rather than merely present today.

Global tool installs (``npm install -g <pkg>``) are not project-dependency
installs — they pull a CLI, not the project's locked graph — so they are
allowed.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

WORKFLOWS = (Path(__file__).resolve().parent.parent / ".github" / "workflows")

# A project dependency install: `npm install [args]` that is NOT `npm install -g`
# (global tooling) and NOT `npm install --global`.
_NPM_INSTALL = re.compile(r"\bnpm\s+install\b")
_NPM_GLOBAL = re.compile(r"\bnpm\s+install\s+(-g|--global)\b")


def _run_lines(step: object):
    """Yield each individual command line of a step's `run:` block, if any."""
    if not isinstance(step, dict):
        return
    run = step.get("run")
    if not isinstance(run, str):
        return
    for line in run.splitlines():
        yield line


def _iter_steps(doc: object):
    jobs = doc.get("jobs", {}) if isinstance(doc, dict) else {}
    for job in jobs.values():
        if isinstance(job, dict):
            for step in job.get("steps", []) or []:
                yield step


def test_ci_and_release_npm_installs_are_lockfile_pinned():
    offenders = []
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        doc = yaml.safe_load(wf.read_text())
        for step in _iter_steps(doc):
            for line in _run_lines(step):
                if _NPM_INSTALL.search(line) and not _NPM_GLOBAL.search(line):
                    offenders.append(f"{wf.name}: {line.strip()}")
    assert not offenders, (
        "unpinned `npm install` found in a workflow (use `npm ci` so the build "
        "fails on lockfile drift instead of silently resolving):\n"
        + "\n".join(offenders)
    )
