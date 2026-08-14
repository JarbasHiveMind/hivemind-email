"""Offline tests for EmailBridge.

Verifies the "answers ALL users" semantics: any email that lands in the
mailbox is treated as an utterance and answered, with no allowlist gate by
default; an explicit ``allowed_senders`` set can restrict this. The
HiveMind bus client is stubbed out entirely -- no live hive needed.
"""
import time
from typing import List
from unittest.mock import MagicMock, patch

from hivemind_email.bridge import EmailBridge
from hivemind_email.carrier import EmailMessage


class _FakeTransport:
    def __init__(self, inbox=None) -> None:
        self._inbox: List[EmailMessage] = inbox or []
        self.sent: List[dict] = []
        self.from_addr = "bridge@example.com"

    def send(self, to_addr: str, subject: str, body: str, **_) -> None:
        self.sent.append({"to": to_addr, "subject": subject, "body": body})

    def poll(self, limit: int = 200) -> List[EmailMessage]:
        out, self._inbox = self._inbox, []
        return out[:limit]


def _make_bridge(transport, allowed_senders=None):
    bridge = EmailBridge(
        transport=transport,
        hive_host="127.0.0.1",
        hive_port=5678,
        hive_key="testkey",
        poll_seconds=99999,
        allowed_senders=allowed_senders,
    )
    fake_client = MagicMock()
    fake_client.ask.return_value = "the answer"
    bridge._hm_client = fake_client
    bridge._connected.set()
    return bridge, fake_client


def _wait_for(predicate, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


class TestEmailBridgeAnswersEveryone:

    def test_unknown_sender_gets_answered_by_default(self):
        """No allowlist configured: EVERY sender is answered."""
        transport = _FakeTransport([
            EmailMessage(subject="hi", text="what time is it", sender="stranger@example.com"),
        ])
        bridge, client = _make_bridge(transport)
        bridge._poll_once()

        assert _wait_for(lambda: len(transport.sent) == 1)
        assert transport.sent[0]["to"] == "stranger@example.com"
        assert transport.sent[0]["body"] == "the answer"
        client.ask.assert_called_once()
        ctx = client.ask.call_args.kwargs["context"]
        assert ctx["source"] == "stranger@example.com"
        assert ctx["session_id"] == "email-bridge-stranger@example.com"
        bridge.stop()

    def test_allowlist_blocks_non_members_when_configured(self):
        transport = _FakeTransport([
            EmailMessage(subject="hi", text="hello", sender="not-allowed@example.com"),
        ])
        bridge, client = _make_bridge(transport, allowed_senders={"friend@example.com"})
        bridge._poll_once()

        time.sleep(0.1)
        assert transport.sent == []
        client.ask.assert_not_called()
        bridge.stop()

    def test_allowlist_admits_members(self):
        transport = _FakeTransport([
            EmailMessage(subject="hi", text="hello", sender="friend@example.com"),
        ])
        bridge, client = _make_bridge(transport, allowed_senders={"friend@example.com"})
        bridge._poll_once()

        assert _wait_for(lambda: len(transport.sent) == 1)
        bridge.stop()

    def test_own_mail_is_skipped(self):
        transport = _FakeTransport([
            EmailMessage(subject="hi", text="hello", sender="bridge@example.com"),
        ])
        bridge, client = _make_bridge(transport)
        bridge._poll_once()

        time.sleep(0.1)
        assert transport.sent == []
        client.ask.assert_not_called()
        bridge.stop()

    def test_empty_body_is_ignored(self):
        transport = _FakeTransport([
            EmailMessage(subject="hi", text="   ", sender="stranger@example.com"),
        ])
        bridge, client = _make_bridge(transport)
        bridge._poll_once()

        time.sleep(0.1)
        assert transport.sent == []
        bridge.stop()

    def test_reply_subject_prefixed(self):
        transport = _FakeTransport([
            EmailMessage(subject="question", text="ask me anything", sender="a@example.com"),
        ])
        bridge, client = _make_bridge(transport)
        bridge._poll_once()

        assert _wait_for(lambda: len(transport.sent) == 1)
        assert transport.sent[0]["subject"] == "Re: question"
        bridge.stop()

    def test_two_senders_get_independent_sessions(self):
        transport = _FakeTransport([
            EmailMessage(subject="q1", text="hello from A", sender="a@example.com"),
            EmailMessage(subject="q2", text="hello from B", sender="b@example.com"),
        ])
        bridge, client = _make_bridge(transport)
        bridge._poll_once()

        assert _wait_for(lambda: len(transport.sent) == 2)
        recipients = {m["to"] for m in transport.sent}
        assert recipients == {"a@example.com", "b@example.com"}
        sessions = {c.kwargs["context"]["session_id"] for c in client.ask.call_args_list}
        assert sessions == {"email-bridge-a@example.com", "email-bridge-b@example.com"}
        bridge.stop()
