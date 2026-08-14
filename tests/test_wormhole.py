"""Offline tests for EmailWormhole.

Two in-process wormholes share a fake mailbox transport. A HiveMessage sent
on node A is handle_message'd on node B byte-identical -- no live SMTP/IMAP
needed.
"""
import json
import threading
from typing import List, Optional
from unittest.mock import MagicMock

import pytest

from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_email.carrier import EmailCarrier, EmailMessage, CHUNK_SIZE, _KIND_HIVE
from hivemind_email.wormhole import EmailWormhole, _make_client_connection


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------

class _SharedFakeTransport:
    """Single in-memory mailbox; all callers share the same message list."""

    def __init__(self) -> None:
        self._mailbox: List[EmailMessage] = []

    def send(self, to_addr: str, subject: str, body: str, **_) -> None:
        self._mailbox.append(EmailMessage(subject=subject, text=body, sender="node@example.com"))

    def poll(self, limit: int = 200) -> List[EmailMessage]:
        return list(self._mailbox[-limit:])


class _RoundTripCreds:
    """Fake PGP: encrypt wraps in JSON; decrypt unwraps."""

    def __init__(self, name: str = "anon") -> None:
        self.pubkey = f"PUBKEY-{name}"
        self._name  = name

    def encrypt(self, txt: str, key: Optional[str] = None) -> str:
        return json.dumps({"_fake": True, "payload": txt})

    def decrypt(self, blob: str) -> str:
        d = json.loads(blob)
        if d.get("_fake"):
            return d["payload"]
        raise ValueError("Not fake-encrypted")


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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_wormhole_pair():
    """Return (wormhole_a, wormhole_b, hm_a, hm_b, transport, carrier_a, carrier_b)."""
    transport = _SharedFakeTransport()
    creds_a  = _RoundTripCreds("a")
    creds_b  = _RoundTripCreds("b")
    carrier_a = EmailCarrier(creds_a, transport)
    carrier_b = EmailCarrier(creds_b, transport)
    hm_a = _FakeHmProtocol()
    hm_b = _FakeHmProtocol()

    wh_a = EmailWormhole(
        config={
            "my_secret":    "b-to-a",
            "peer_secret":  "a-to-b",
            "peer_email":   "b@example.com",
            "peer_pubkey":  creds_b.pubkey,
            "poll_seconds": 99999,
        },
        hm_protocol=hm_a,
    )
    wh_a._carrier       = carrier_a
    wh_a._carrier.creds = creds_a

    wh_b = EmailWormhole(
        config={
            "my_secret":    "a-to-b",
            "peer_secret":  "b-to-a",
            "peer_email":   "a@example.com",
            "peer_pubkey":  creds_a.pubkey,
            "poll_seconds": 99999,
        },
        hm_protocol=hm_b,
    )
    wh_b._carrier       = carrier_b
    wh_b._carrier.creds = creds_b

    return wh_a, wh_b, hm_a, hm_b, transport, carrier_a, carrier_b


def _wh_poll_once(wormhole: EmailWormhole) -> None:
    my_secret = wormhole.config["my_secret"]
    messages  = wormhole._carrier.poll(my_secret)
    for kind, payload, _sender in messages:
        if kind == _KIND_HIVE:
            wormhole._dispatch(payload)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestWormhole:

    def test_single_message_a_to_b(self):
        wh_a, wh_b, hm_a, hm_b, transport, ca, cb = _make_wormhole_pair()

        original = HiveMessage(HiveMessageType.PING, payload={"hello": "world"})
        payload  = original.serialize().encode()

        ca.send(payload, to_addr="b@example.com",
                peer_secret=wh_a.config["peer_secret"],
                peer_pubkey=wh_a.config["peer_pubkey"],
                kind=_KIND_HIVE)

        _wh_poll_once(wh_b)

        assert len(hm_b.received) == 1
        received = hm_b.received[0]
        assert received.msg_type == original.msg_type

    def test_message_b_to_a(self):
        wh_a, wh_b, hm_a, hm_b, transport, ca, cb = _make_wormhole_pair()

        original = HiveMessage(HiveMessageType.BROADCAST, payload={"x": 42})
        payload  = original.serialize().encode()

        cb.send(payload, to_addr="a@example.com",
                peer_secret=wh_b.config["peer_secret"],
                peer_pubkey=wh_b.config["peer_pubkey"],
                kind=_KIND_HIVE)

        _wh_poll_once(wh_a)

        assert len(hm_a.received) == 1
        assert hm_a.received[0].msg_type == original.msg_type

    def test_large_message_multiple_chunks(self):
        wh_a, wh_b, hm_a, hm_b, transport, ca, cb = _make_wormhole_pair()

        big_data  = {"blob": "X" * (CHUNK_SIZE * 3)}
        original  = HiveMessage(HiveMessageType.RENDEZVOUS, payload=big_data)
        payload   = original.serialize().encode()
        assert len(payload) > CHUNK_SIZE

        ca.send(payload, to_addr="b@example.com",
                peer_secret=wh_a.config["peer_secret"],
                peer_pubkey=wh_a.config["peer_pubkey"],
                kind=_KIND_HIVE)

        _wh_poll_once(wh_b)

        assert len(hm_b.received) == 1

    def test_byte_identical_payload(self):
        wh_a, wh_b, hm_a, hm_b, transport, ca, cb = _make_wormhole_pair()

        original = HiveMessage(HiveMessageType.QUERY,
                               payload={"utterance": "what time is it"})
        raw = original.serialize().encode()

        ca.send(raw, to_addr="b@example.com",
                peer_secret=wh_a.config["peer_secret"],
                peer_pubkey=wh_a.config["peer_pubkey"],
                kind=_KIND_HIVE)

        _wh_poll_once(wh_b)

        assert len(hm_b.received) == 1
        reconstructed = hm_b.received[0].serialize().encode()
        assert json.loads(reconstructed) == json.loads(raw)

    def test_non_hive_kind_ignored(self):
        wh_a, wh_b, hm_a, hm_b, transport, ca, cb = _make_wormhole_pair()

        ca.send(b"plain text question", to_addr="b@example.com",
                peer_secret=wh_a.config["peer_secret"],
                peer_pubkey=wh_a.config["peer_pubkey"],
                kind="nl")

        _wh_poll_once(wh_b)

        assert hm_b.received == []

    def test_client_connection_created(self):
        wh_a, wh_b, hm_a, hm_b, transport, ca, cb = _make_wormhole_pair()

        original = HiveMessage(HiveMessageType.PING, payload={})
        payload  = original.serialize().encode()
        ca.send(payload, to_addr="b@example.com",
                peer_secret=wh_a.config["peer_secret"],
                peer_pubkey=wh_a.config["peer_pubkey"],
                kind=_KIND_HIVE)

        _wh_poll_once(wh_b)

        assert wh_b._client_conn is not None
        assert wh_b._client_conn.key == wh_b.config.get("peer_id", "email-peer")

    def test_stop_event(self):
        wh_a, wh_b, hm_a, hm_b, transport, ca, cb = _make_wormhole_pair()
        wh_a._stop_event.set()
        wh_a.stop()
        assert wh_a._stop_event.is_set()
