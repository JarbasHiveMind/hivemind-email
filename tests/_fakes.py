"""Stubs shared by more than one test file.

This module is deliberately NOT under a ``tests`` package. ``tests/`` has no
``__init__.py``, so pytest puts ``tests/`` itself on ``sys.path`` and a direct
``python tests/<file>.py`` run does the same. ``from _fakes import X`` then
resolves the same way in both, and neither needs the repository root on
``sys.path``.

That last point is the whole reason this file exists. A shared stub reached as
``from tests.<file> import X`` requires the repository root on ``sys.path``,
and the root carries a second copy of the package under test. The suite then
imports the working tree instead of the installed wheel, and ``build_tests``
cannot see a packaging defect. See ``test_every_test_file_imports_alone.py``
for the guard.
"""
import threading
from typing import List

from hivemind_bus_client.message import HiveMessage


class _FakeIdentity:
    private_key = None


class _FakeHmProtocol:
    def __init__(self) -> None:
        self.received: List[HiveMessage] = []
        self.lock     = threading.Lock()
        self.identity = _FakeIdentity()
        from poorman_handshake.asymmetric import HandShake
        self.identity_rsa_key = HandShake(None).private_key

    def handle_message(self, msg: HiveMessage, client) -> None:
        with self.lock:
            self.received.append(msg)
