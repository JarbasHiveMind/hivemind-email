"""Every test file imports cleanly when run on its own, and none of them
reaches a sibling through a ``tests`` package.

``tests`` is NOT a package: it ships no ``__init__.py``. Under pytest that
puts ``tests/`` itself on ``sys.path`` rather than the repository root, and
``python tests/<file>.py`` does the same, so ``from _fakes import X`` resolves
in both. See ``tests/_fakes.py``.

Two things go wrong if the convention breaks, and they have DIFFERENT shapes.

A module-level ``from tests.x import y`` raises ``ModuleNotFoundError: No
module named 'tests'`` on a direct run, before the file does anything. That is
what ``test_a_direct_run_imports_without_the_repository_root`` catches, and it
is the shape that made ``test_coded_disconnect.py`` the only file in the suite
to exit 1.

The SAME import deferred inside a function is invisible to that check: the
file imports fine and the call fails later. Under pytest it does not fail at
all, because an ``__init__.py`` would put the repository root on ``sys.path``,
and the root carries a second copy of the package under test. The suite then
exercises the working tree instead of the installed wheel and ``build_tests``
cannot see a packaging defect. Deferring the import hides the breakage
instead of removing it, which is why
``test_no_file_imports_the_tests_package`` reads the source and does not rely
on a run failing.

And the root gets back onto ``sys.path`` in THREE ways, not one, which is why
``test_the_repository_root_is_not_on_syspath`` is the load-bearing check here
rather than the ``__init__.py`` check: a ``tests/__init__.py``, a ``conftest.py``
at the repository root -- an EMPTY one is enough -- and running the suite as
``python -m pytest`` instead of ``pytest``, which puts the cwd on the path. The
first two checks read the source and see none of that; the third reads what the
interpreter actually has.

A direct run exiting 0 is not a pass. These files define tests and run none
of them on their own, and that is the whole expectation here: the file
IMPORTS. What it does under pytest is every other test's business.
"""
import ast
import json
import pathlib
import subprocess
import sys
import urllib.parse
import urllib.request
from importlib import metadata

import pytest

import hivemind_email

TESTS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
# rglob, not glob: a nested directory under tests/ is the one place a sibling
# could hide a cross-import that a flat scan never reads. Names are relative to
# TESTS_DIR so the direct-run case below can still spell the path.
TEST_FILES = sorted(str(p.relative_to(TESTS_DIR)) for p in TESTS_DIR.rglob("test_*.py"))
# the shared stubs are not a test file and are imported by two of them
SCANNED_FILES = sorted(str(p.relative_to(TESTS_DIR)) for p in TESTS_DIR.rglob("*.py"))


def _tests_package_imports(source, filename="<probe>"):
    """Return one description per import of the ``tests`` package, any depth.

    ``ast.walk`` does not care whether the import sits at module level or
    inside a function, which is the point: the deferred form is the one a
    direct run cannot see.
    """
    found = []
    for node in ast.walk(ast.parse(source, filename)):
        if isinstance(node, ast.ImportFrom):
            # a relative import has no module name to inspect
            if node.level == 0 and node.module and (
                    node.module == "tests" or node.module.startswith("tests.")):
                found.append(f"line {node.lineno}: from {node.module} import ...")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "tests" or alias.name.startswith("tests."):
                    found.append(f"line {node.lineno}: import {alias.name}")
    return found


def _editable_install_of_this_tree():
    """True when ``hivemind_email`` is installed editable FROM THIS TREE.

    PEP 610: an editable install writes ``direct_url.json`` with
    ``dir_info.editable`` true and the source directory as the url. Both
    ``pip install -e`` and ``uv pip install -e`` write it, and the coverage
    job here uses the second. The url check is what keeps this narrow: an
    editable install of a DIFFERENT checkout would still shadow this one.
    """
    for dist in metadata.distributions():
        name = (dist.metadata["Name"] or "").lower().replace("_", "-")
        if name != "hivemind-email":
            continue
        # EVERY match is read, not the first. With the root on sys.path an
        # in-tree hivemind_email.egg-info is a distribution too, and it wins
        # the lookup by name while carrying no direct_url.json at all.
        raw = dist.read_text("direct_url.json")
        if not raw:
            continue
        info = json.loads(raw)
        if not info.get("dir_info", {}).get("editable"):
            continue
        parsed = urllib.parse.urlparse(info.get("url", ""))
        if parsed.scheme != "file":
            continue
        if pathlib.Path(
                urllib.request.url2pathname(parsed.path)).resolve() == REPO_ROOT:
            return True
    return False


def test_the_suite_was_found():
    """A glob that matched nothing would make every case below vacuous."""
    assert len(TEST_FILES) >= 5, TEST_FILES
    assert "test_coded_disconnect.py" in TEST_FILES
    assert "_fakes.py" in SCANNED_FILES, SCANNED_FILES


def test_the_repository_root_is_not_on_syspath():
    """The load-bearing check: the root is where the second copy lives.

    Every way the shadow comes back ends here, so this is the one assertion
    that does not need to know HOW it came back. Measured on this repository:
    the root is absent for a wheel install under ``pytest`` (the build_tests
    shape), and present for all three defect shapes on that same install --
    ``tests/__init__.py`` restored, an empty ``conftest.py`` at the root, and
    ``python -m pytest``, which puts the cwd on the path.

    It is deliberately NOT an assertion that the package resolves to
    site-packages. That is False for a healthy editable install, so it would
    fail this repository's own coverage job; see ``_fakes.py``.

    One shape carries the root legitimately: an editable install of THIS tree.
    The coverage job makes it -- ``uv pip install -e .`` and then
    ``python -m pytest`` -- and there the root shadows nothing, because the
    tree IS the install. That case gets the assertion it can carry: the
    package resolves inside the repository root, which is the proof there is
    no second copy. Every other shape, editable or not, reaches the assertion
    below. ``build_tests`` installs the wheel, so the load-bearing check runs
    there on every pull request.
    """
    if _editable_install_of_this_tree():
        package = pathlib.Path(hivemind_email.__file__).resolve()
        assert package.parent.parent == REPO_ROOT, (
            "the install says editable from " + str(REPO_ROOT) + " but "
            "hivemind_email resolves to " + str(package) + ", so a second "
            "copy is on the path after all")
        pytest.skip(
            "editable install of this tree: the repository root on sys.path "
            "resolves to the install itself, so there is nothing to shadow. "
            "The wheel shape in build_tests carries this check.")
    assert str(REPO_ROOT) not in sys.path, (
        f"the repository root {REPO_ROOT} is on sys.path, so an import of "
        "hivemind_email can resolve to the WORKING TREE instead of the "
        "installed wheel, and build_tests cannot detect a packaging defect. "
        "Three things do this: a tests/__init__.py, a conftest.py at the "
        "repository root, and running the suite as `python -m pytest` instead "
        "of `pytest`.\nsys.path: " + repr(sys.path))


def test_the_tests_directory_is_not_a_package():
    """``tests/__init__.py`` is ONE of the things that puts the repository root
    on sys.path, not the thing; the check above is what covers the others.

    It is still worth naming on its own, because it is the shape this
    repository actually had and its message can say what to do about it.
    """
    assert not (TESTS_DIR / "__init__.py").exists(), (
        "tests/__init__.py is back. It makes the repository root importable, "
        "so the suite resolves hivemind_email to the working tree instead of "
        "the installed wheel and build_tests stops being able to detect a "
        "packaging defect.")


@pytest.mark.parametrize("name", SCANNED_FILES)
def test_no_file_imports_the_tests_package(name):
    """Catches the deferred form, which the direct run below cannot.

    Reads the source rather than running it, because an import inside a
    function fails only when that function is called, and under pytest with an
    ``__init__.py`` present it does not fail at all.
    """
    found = _tests_package_imports((TESTS_DIR / name).read_text(), name)
    assert not found, (
        f"{name} reaches a sibling through the 'tests' package:\n  "
        + "\n  ".join(found)
        + "\nImport the shared stub as 'from _fakes import X' instead. A "
          "'tests.' import needs the repository root on sys.path, and that is "
          "what makes the suite import the working tree over the wheel.")


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
        f"A module-level 'from tests.x import y' is the usual cause; import "
        f"the shared stub as 'from _fakes import X'.\n{result.stderr[-800:]}")


def test_the_scan_catches_a_deferred_cross_import():
    """The new check must fail on the thing it exists to catch.

    This is the case the direct run misses, so a scan that quietly matched
    nothing would look identical to a healthy suite.
    """
    deferred = (
        "def _connection():\n"
        "    from tests.test_wormhole import _FakeHmProtocol\n"
        "    return _FakeHmProtocol()\n")
    assert _tests_package_imports(deferred) == [
        "line 2: from tests.test_wormhole import ..."]

    # the module-level form, and the plain `import tests.x` spelling
    assert _tests_package_imports("from tests import x\n")
    assert _tests_package_imports("import tests.test_wormhole\n")

    # and it must not fire on what the convention asks for
    assert _tests_package_imports("from _fakes import _FakeHmProtocol\n") == []
    assert _tests_package_imports("from hivemind_email.carrier import X\n") == []
    # a module whose name merely starts with the same letters is not the package
    assert _tests_package_imports("from testsuite_helpers import X\n") == []


def test_the_guard_catches_a_module_level_cross_import():
    """The direct-run check must fail on the thing IT exists to catch.

    Without this, a guard that passed for the wrong reason (a swallowed
    error, a wrong cwd) would look identical to a healthy suite.

    The offender is written into ``tests/`` and not into a ``tmp_path``, and it
    has to be: the defect under test is what ``sys.path`` looks like when a file
    is run as ``python tests/<file>.py``, and a file somewhere else gets a
    different ``sys.path``. It would prove nothing about this suite. The write
    is removed in a ``finally``.
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
