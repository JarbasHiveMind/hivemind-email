"""Offline unit tests for EmailCarrier.

All tests run without a live SMTP/IMAP connection -- a stub transport and
stub Credentials are used throughout, mirroring hivemind-usenet's
test_carrier.py strategy.
"""
import base64
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch

import pytest

from hivemind_email.carrier import (
    CARRIER_VERSION,
    CHUNK_SIZE,
    CarrierBuffer,
    EmailCarrier,
    EmailMessage,
    Frame,
    SMTPIMAPTransport,
    _KIND_HIVE,
    _KIND_NL,
)


# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------

class _FakeTransport:
    """In-memory SMTP+IMAP stub: send() appends, poll() returns everything sent."""

    def __init__(self) -> None:
        self._mailbox: List[EmailMessage] = []

    def send(self, to_addr: str, subject: str, body: str, **_) -> None:
        self._mailbox.append(EmailMessage(subject=subject, text=body, sender="sender@example.com"))

    def poll(self, limit: int = 200) -> List[EmailMessage]:
        return list(self._mailbox[-limit:])

    def clear(self) -> None:
        self._mailbox.clear()


class _RoundTripCreds:
    """Stub Credentials: encrypt -> store -> decrypt, in-process only."""

    def __init__(self) -> None:
        self.pubkey = "FAKE-PUBKEY"

    def encrypt(self, txt: str, key: Optional[str] = None) -> str:
        return json.dumps({"_fake": True, "payload": txt})

    def decrypt(self, blob: str) -> str:
        d = json.loads(blob)
        if d.get("_fake"):
            return d["payload"]
        raise ValueError("Not a fake-encrypted blob")


# ---------------------------------------------------------------------------
# Tests: Frame dataclass
# ---------------------------------------------------------------------------

class TestFrame:
    def test_round_trip_json(self):
        f = Frame(v=1, mid="abc", seq=0, n=1, kind=_KIND_HIVE,
                  data=base64.b64encode(b"hello").decode())
        assert Frame.from_json(f.to_json()) == f

    def test_frozen(self):
        f = Frame(v=1, mid="x", seq=0, n=1, kind=_KIND_NL, data="dGVzdA==")
        with pytest.raises((AttributeError, TypeError)):
            f.seq = 99  # frozen dataclass

    def test_kind_preserved(self):
        for k in (_KIND_HIVE, _KIND_NL):
            f = Frame(v=1, mid="m", seq=0, n=1, kind=k, data="")
            assert Frame.from_json(f.to_json()).kind == k


# ---------------------------------------------------------------------------
# Tests: CarrierBuffer (reassembly + dedup)
# ---------------------------------------------------------------------------

class TestCarrierBuffer:
    def _frame(self, mid: str, seq: int, n: int, data: bytes, kind: str = _KIND_HIVE) -> Frame:
        return Frame(v=1, mid=mid, seq=seq, n=n, kind=kind,
                     data=base64.b64encode(data).decode())

    def test_single_chunk_completes(self):
        buf = CarrierBuffer()
        result = buf.ingest(self._frame("m1", 0, 1, b"hello"), sender="a@b.com")
        assert result is not None
        kind, payload, sender = result
        assert payload == b"hello"
        assert kind == _KIND_HIVE
        assert sender == "a@b.com"

    def test_multi_chunk_reassembly(self):
        buf = CarrierBuffer()
        data = b"ABCDEFGHIJ"
        mid  = "m2"
        assert buf.ingest(self._frame(mid, 0, 3, data[0:4])) is None
        assert buf.ingest(self._frame(mid, 1, 3, data[4:8])) is None
        result = buf.ingest(self._frame(mid, 2, 3, data[8:]))
        assert result is not None
        _, payload, _ = result
        assert payload == data

    def test_out_of_order_delivery(self):
        buf = CarrierBuffer()
        data = b"123456789"
        mid  = "m3"
        assert buf.ingest(self._frame(mid, 2, 3, data[6:])) is None
        assert buf.ingest(self._frame(mid, 0, 3, data[0:3])) is None
        result = buf.ingest(self._frame(mid, 1, 3, data[3:6]))
        assert result is not None
        _, payload, _ = result
        assert payload == data

    def test_duplicate_seq_dropped(self):
        buf = CarrierBuffer()
        mid = "m4"
        f = self._frame(mid, 0, 2, b"part1")
        assert buf.ingest(f) is None
        assert buf.ingest(f) is None
        result = buf.ingest(self._frame(mid, 1, 2, b"part2"))
        assert result is not None
        _, payload, _ = result
        assert payload == b"part1part2"
        assert buf.ingest(f) is None

    def test_independent_messages(self):
        buf = CarrierBuffer()
        r1 = buf.ingest(self._frame("m5", 0, 1, b"msg-A"))
        r2 = buf.ingest(self._frame("m6", 0, 1, b"msg-B"))
        assert r1 is not None and r1[1] == b"msg-A"
        assert r2 is not None and r2[1] == b"msg-B"


# ---------------------------------------------------------------------------
# Tests: hSub matching
# ---------------------------------------------------------------------------

class TestHSub:
    def test_match(self):
        from remailers import create_hsub, match_hsub
        secret = "captain-dolphin"
        subject = create_hsub(secret)
        assert match_hsub(subject, secret)

    def test_no_match(self):
        from remailers import create_hsub, match_hsub
        subject = create_hsub("secret-A")
        assert not match_hsub(subject, "secret-B")

    def test_wrong_length_no_match(self):
        from remailers import match_hsub
        assert not match_hsub("tooshort", "anything")


# ---------------------------------------------------------------------------
# Tests: PGP round-trip with real Credentials
# ---------------------------------------------------------------------------

class TestPGPRoundTrip:
    def test_encrypt_decrypt(self, tmp_path):
        from remailers.keys import Credentials
        key_path = str(tmp_path / "test.asc")
        creds = Credentials(key_path)
        plaintext = "Hello, HiveMind over email!"
        ciphertext = creds.encrypt(plaintext, creds.pubkey)
        assert ciphertext != plaintext
        result = creds.decrypt(ciphertext)
        assert result == plaintext

    def test_cross_node_encrypt_decrypt(self, tmp_path):
        from remailers.keys import Credentials
        node_a = Credentials(str(tmp_path / "node_a.asc"))
        node_b = Credentials(str(tmp_path / "node_b.asc"))
        msg = "cross-node message"
        ct = node_b.encrypt(msg, node_a.pubkey)
        assert node_a.decrypt(ct) == msg


# ---------------------------------------------------------------------------
# Tests: EmailCarrier send/poll round-trip (stub, no network)
# ---------------------------------------------------------------------------

class TestEmailCarrier:
    def _make_pair(self) -> Tuple["EmailCarrier", "EmailCarrier", "_FakeTransport"]:
        """Two carriers sharing the same fake mailbox transport."""
        transport = _FakeTransport()
        creds_a = _RoundTripCreds()
        creds_b = _RoundTripCreds()
        carrier_a = EmailCarrier(creds_a, transport, chunk_size=CHUNK_SIZE)
        carrier_b = EmailCarrier(creds_b, transport, chunk_size=CHUNK_SIZE)
        return carrier_a, carrier_b, transport

    def test_single_chunk_round_trip(self):
        ca, cb, _ = self._make_pair()
        payload = b"hello email"
        ca.send(payload, to_addr="b@example.com", peer_secret="s2b", peer_pubkey=cb.creds.pubkey)
        results = cb.poll("s2b")
        assert len(results) == 1
        kind, data, sender = results[0]
        assert kind == _KIND_HIVE
        assert data == payload
        assert sender == "sender@example.com"

    def test_kind_nl_round_trip(self):
        ca, cb, _ = self._make_pair()
        ca.send(b"what is the weather?", to_addr="b@example.com", peer_secret="nlsecret",
                peer_pubkey=cb.creds.pubkey, kind=_KIND_NL)
        results = cb.poll("nlsecret")
        assert len(results) == 1
        assert results[0][0] == _KIND_NL

    def test_wrong_secret_yields_nothing(self):
        ca, cb, _ = self._make_pair()
        ca.send(b"secret msg", to_addr="b@example.com", peer_secret="correct", peer_pubkey=cb.creds.pubkey)
        results = cb.poll("wrong")
        assert results == []

    def test_multi_chunk_reassembly(self):
        ca, cb, _ = self._make_pair()
        payload = bytes(range(256)) * 50   # 12 800 bytes -> 3 chunks at 6000
        ca.send(payload, to_addr="b@example.com", peer_secret="ms", peer_pubkey=cb.creds.pubkey)
        results = cb.poll("ms")
        assert len(results) == 1
        assert results[0][1] == payload

    def test_out_of_order_multi_chunk(self):
        transport = _FakeTransport()
        creds  = _RoundTripCreds()
        sender = EmailCarrier(creds, transport, chunk_size=10)

        payload = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # 26 bytes -> 3 chunks@10
        sender.send(payload, to_addr="b@example.com", peer_secret="oo", peer_pubkey=creds.pubkey)

        transport._mailbox.reverse()

        receiver = EmailCarrier(creds, transport, chunk_size=10)
        results  = receiver.poll("oo")
        assert len(results) == 1
        assert results[0][1] == payload

    def test_duplicate_mails_not_double_counted(self):
        transport = _FakeTransport()
        creds  = _RoundTripCreds()
        carrier = EmailCarrier(creds, transport, chunk_size=CHUNK_SIZE)
        carrier.send(b"unique", to_addr="b@example.com", peer_secret="dd", peer_pubkey=creds.pubkey)
        transport._mailbox = transport._mailbox * 2

        results = carrier.poll("dd")
        assert len(results) == 1

    def test_invalid_kind_raises(self):
        transport = _FakeTransport()
        creds  = _RoundTripCreds()
        c = EmailCarrier(creds, transport)
        with pytest.raises(ValueError, match="Invalid kind"):
            c.send(b"x", to_addr="b@example.com", peer_secret="s", peer_pubkey=creds.pubkey, kind="invalid")

    def test_empty_payload(self):
        transport = _FakeTransport()
        creds  = _RoundTripCreds()
        c = EmailCarrier(creds, transport, chunk_size=10)
        c.send(b"", to_addr="b@example.com", peer_secret="empty", peer_pubkey=creds.pubkey)
        results = c.poll("empty")
        assert len(results) == 1
        assert results[0][1] == b""


# ---------------------------------------------------------------------------
# SMTPIMAPTransport.poll() -- backed by mail_monitor's EmailClient
# ---------------------------------------------------------------------------

class TestSMTPIMAPTransportPoll:
    """poll() must delegate IMAP fetch/parse to mail_monitor.EmailClient."""

    def _make_transport(self, mark_seen: bool = True) -> SMTPIMAPTransport:
        return SMTPIMAPTransport(
            smtp_host="smtp.example.com",
            smtp_user="me@example.com",
            smtp_password="pw",
            imap_host="imap.example.com",
            imap_user="me@example.com",
            imap_password="pw",
            mark_seen=mark_seen,
        )

    @patch("hivemind_email.carrier.EmailClient")
    def test_plain_message_parsed(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value = client
        client.list_new_emails.return_value = [
            {"sender": "Alice", "email": "alice@example.com",
             "payload": "hello world", "subject": "hi there", "ts": 0},
        ]

        transport = self._make_transport()
        out = transport.poll()

        assert len(out) == 1
        assert out[0].sender == "alice@example.com"
        assert out[0].subject == "hi there"
        assert out[0].text.strip() == "hello world"
        mock_client_cls.assert_called_once_with(
            "me@example.com", "pw", "imap.example.com", 993, "inbox",
        )
        client.list_new_emails.assert_called_once_with(mark_as_seen=True)

    @patch("hivemind_email.carrier.EmailClient")
    def test_multipart_prefers_plain_text(self, mock_client_cls):
        # mail_monitor.EmailClient.get_body already resolves multipart bodies
        # to plain text before poll() ever sees them.
        client = MagicMock()
        mock_client_cls.return_value = client
        client.list_new_emails.return_value = [
            {"sender": "bob@example.com", "email": "bob@example.com",
             "payload": "plain body", "subject": "multi", "ts": 0},
        ]

        transport = self._make_transport()
        out = transport.poll()

        assert len(out) == 1
        assert out[0].text.strip() == "plain body"

    @patch("hivemind_email.carrier.EmailClient")
    def test_no_unseen_returns_empty(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value = client
        client.list_new_emails.return_value = []

        transport = self._make_transport()
        assert transport.poll() == []

    @patch("hivemind_email.carrier.EmailClient")
    def test_mark_seen_false_passed_through(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value = client
        client.list_new_emails.return_value = [
            {"sender": "c@example.com", "email": "c@example.com",
             "payload": "body", "subject": "s", "ts": 0},
        ]

        transport = self._make_transport(mark_seen=False)
        transport.poll()

        client.list_new_emails.assert_called_once_with(mark_as_seen=False)

    @patch("hivemind_email.carrier.EmailClient")
    def test_limit_truncates_results(self, mock_client_cls):
        client = MagicMock()
        mock_client_cls.return_value = client
        client.list_new_emails.return_value = [
            {"sender": f"u{i}@example.com", "email": f"u{i}@example.com",
             "payload": "body", "subject": "s", "ts": 0}
            for i in range(5)
        ]

        transport = self._make_transport()
        out = transport.poll(limit=2)

        assert len(out) == 2
