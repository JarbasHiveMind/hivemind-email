"""Every test file imports cleanly when run on its own.

``tests`` is a package: it ships an ``__init__.py``, and under pytest the
repository root is on ``sys.path``, so an absolute ``from tests.x import y``
resolves. A DIRECT run does not work that way. ``python tests/<file>.py``
puts ``tests/`` itself on ``sys.path``, not the repository root, so the
``tests`` package is not importable and any module-level cross-import raises
``ModuleNotFoundError: No module named 'tests'`` before the file does
anything.

That made ``test_coded_disconnect.py`` the only file in the suite to exit 1
on a direct run, while the other four exited 0. The fix was to defer its one
cross-import to call time rather than add an ``__init__.py`` (there is one
already) or a ``sys.path`` workaround.

THIS IS THE GUARD, not the fix. The convention is cheap to break again: one
module-level ``from tests.x import y`` in any file restores the old
behaviour, and nothing else in the suite would notice, because pytest keeps
passing either way.

A direct run exiting 0 is not a pass. These files define tests and run none
of them on their own, and that is the whole expectation here: the file
IMPORTS. What it does under pytest is every other test's business.
"""
import pathlib
import subprocess
import sys

import pytest

TESTS_DIR = pathlib.Path(__file__).resolve().parent
TEST_FILES = sorted(p.name for p in TESTS_DIR.glob("test_*.py"))


def test_the_suite_was_found():
    """A glob that matched nothing would make every case below vacuous."""
    assert len(TEST_FILES) >= 5, TEST_FILES
    assert "test_coded_disconnect.py" in TEST_FILES


@pytest.mark.parametrize("name", TEST_FILES)
def test_a_direct_run_imports_without_the_repository_root(name):
    """Run the file the way a developer checking one file would.

    ``cwd`` is the repository root and the file is named by path, which is
    what puts ``tests/`` on sys.path rather than the root. Running it as
    ``python -m tests.<name>`` would import the package and prove nothing.
    """
    result = subprocess.run(
        [sys.executable, str(TESTS_DIR.name + "/" + name)],
        cwd=TESTS_DIR.parent, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, (
        f"{name} does not import on its own (exit {result.returncode}).\n"
        f"A module-level 'from tests.x import y' is the usual cause; defer it "
        f"to call time.\n{result.stderr[-800:]}")


def test_the_guard_catches_a_module_level_cross_import(tmp_path):
    """The guard must fail on the thing it exists to catch.

    Without this, a guard that passed for the wrong reason (a swallowed
    error, a wrong cwd) would look identical to a healthy suite.
    """
    offender = TESTS_DIR / "_t4612_probe_delete_me.py"
    offender.write_text("from tests.test_wormhole import _FakeHmProtocol\n")
    try:
        result = subprocess.run(
            [sys.executable, f"{TESTS_DIR.name}/{offender.name}"],
            cwd=TESTS_DIR.parent, capture_output=True, text=True, timeout=120)
        assert result.returncode != 0, (
            "a module-level cross-import ran cleanly, so this guard would "
            "not catch the defect it was written for")
        assert "No module named 'tests'" in result.stderr, result.stderr[-400:]
    finally:
        offender.unlink()
