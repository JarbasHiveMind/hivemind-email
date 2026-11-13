"""A close carries a code and a reason, on this transport too.

`HiveMindClientConnection.disconnect` is called WITH a code by the core
server: `non_noise_frame`, `invalid_noise_frame` and `unencrypted_frame` all
pass one, and so do the five origination-permission kicks. This wormhole's
callback took no parameters, so every one of those raised `TypeError` here
instead of closing the peer, and a transport that cannot be closed cannot
enforce a permission.

The other four transports already take `(code=1000, reason="")`. The usenet
wormhole, which is this file's closest sibling, logs both.
"""
import inspect
import unittest
from unittest.mock import MagicMock

# ``_fakes`` is the repo's own fake, so this file does not invent a second one:
# HiveMindClientConnection.__post_init__ reads the protocol's RSA key. It is not
# under a package, so this resolves under pytest and on a direct
# ``python tests/test_coded_disconnect.py`` run alike.
from _fakes import _FakeHmProtocol
from hivemind_email.carrier import EmailCarrier
from hivemind_email.wormhole import _make_client_connection


def _connection():
    return _make_client_connection(
        peer_id="peer-1",
        carrier=MagicMock(spec=EmailCarrier),
        peer_email="b@example.com",
        peer_secret="a-to-b",
        peer_pubkey="pub",
        hm_protocol=_FakeHmProtocol(),
    )


class TestTheCloseTakesACodeAndReason(unittest.TestCase):

    def test_a_coded_close_does_not_raise(self):
        """The call core actually makes."""
        conn = _connection()
        conn.disconnect(1008, "origination permission denied")

    def test_every_close_core_makes_is_accepted(self):
        # the codes core closes with today, each with its reason string
        for code, reason in ((1000, ""),
                             (1003, "unencrypted_frame"),
                             (1008, "invalid_noise_frame"),
                             (1011, "internal error handling hello")):
            with self.subTest(code=code):
                _connection().disconnect(code, reason)

    def test_a_bare_close_still_works(self):
        """The old call shape keeps working, so nothing that closed without
        a code has to change."""
        _connection().disconnect()

    def test_the_signature_matches_the_other_transports(self):
        conn = _connection()
        sig = inspect.signature(conn.disconnect)
        self.assertIn("code", sig.parameters)
        self.assertIn("reason", sig.parameters)
        self.assertEqual(sig.parameters["code"].default, 1000)
        self.assertEqual(sig.parameters["reason"].default, "")

    def test_the_code_and_reason_reach_the_log(self):
        """A close that swallowed its code would pass the calls above and
        still tell an operator nothing about why the peer went away."""
        conn = _connection()
        with unittest.mock.patch("hivemind_email.wormhole.LOG.debug") as dbg:
            conn.disconnect(1008, "origination permission denied")
        said = " ".join(str(c) for c in dbg.call_args_list)
        self.assertIn("1008", said)
        self.assertIn("origination permission denied", said)

    def test_a_newline_in_the_reason_does_not_split_the_log_record(self):
        """A reason is attacker-influenced free text. A newline in it must
        not start a second, attacker-authored log line.

        The raw logged string is read from ``call_args`` directly, not via
        ``str(call_args_list)``: that formats each argument with ``repr()``
        for display and would escape the newline on its own, passing this
        test whether or not the production code escapes anything.
        """
        conn = _connection()
        with unittest.mock.patch("hivemind_email.wormhole.LOG.debug") as dbg:
            conn.disconnect(1008, "rejected\nBcc: attacker@evil.test")
        self.assertEqual(dbg.call_count, 1)
        message = dbg.call_args[0][0]
        self.assertNotIn("\nBcc: attacker@evil.test", message)
        self.assertIn("\\n", message)

