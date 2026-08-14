"""Offline tests for HiveMindEmailClient.

Two in-process carriers share a fake mailbox transport. One carrier is wired
to a stub EmailWormhole (hub side); the other to a HiveMindEmailClient
(satellite side). Messages flow in both directions without any live
SMTP/IMAP connection. Mirrors hivemind-usenet's test_client.py conventions.
"""
import json
import threading
from typing import List, Optional

import pytest

from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_email.carrier import EmailCarrier, EmailMessage, CHUNK_SIZE, _KIND_HIVE
from hivemind_email.client import HiveMindEmailClient
from hivemind_email.wormhole import EmailWormhole


# ---------------------------------------------------------------------------
# Stubs (same pattern as test_wormhole.py)
# ---------------------------------------------------------------------------

class _SharedFakeTransport:
    def __init__(self) -> None:
        self._mailbox: List[EmailMessage] = []

    def send(self, to_addr: str, subject: str, body: str, **_) -> None:
        self._mailbox.append(EmailMessage(subject=subject, text=body, sender="peer@example.com"))

    def poll(self, limit: int = 200) -> List[EmailMessage]:
        return list(self._mailbox[-limit:])


class _RoundTripCreds:
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
    public_key  = "FAKE-PUBKEY"
    password    = "test-password"
    access_key  = "test-access-key"
    site_id     = "test-site"
    name        = "test-node"


class _FakeHmProtocol:
    def __init__(self) -> None:
        self.received: List[HiveMessage] = []
        self.lock      = threading.Lock()
        self.identity  = _FakeIdentity()
        from poorman_handshake.asymmetric import HandShake
        self.identity_rsa_key = HandShake(None).private_key

    def handle_message(self, msg: HiveMessage, client) -> None:
        with self.lock:
            self.received.append(msg)


class _FakeSlaveProtocol:
    def __init__(self) -> None:
        self.received_hello:     List[HiveMessage] = []
        self.received_handshake: List[HiveMessage] = []
        self.received_bus:       List[HiveMessage] = []
        self.received_broadcast: List[HiveMessage] = []
        self.identity = _FakeIdentity()
        self.site_id  = "unknown"
        self.binarize = False

    def bind(self, bus) -> None:
        pass

    def start_handshake(self) -> None:
        pass

    def handle_hello(self, msg: HiveMessage) -> None:
        self.received_hello.append(msg)

    def handle_handshake(self, msg: HiveMessage) -> None:
        self.received_handshake.append(msg)

    def handle_bus(self, msg: HiveMessage) -> None:
        self.received_bus.append(msg)

    def handle_broadcast(self, msg: HiveMessage) -> None:
        self.received_broadcast.append(msg)

    def handle_propagate(self, msg: HiveMessage) -> None:
        pass

    def handle_intercom(self, msg: HiveMessage) -> None:
        pass

    def handle_illegal_msg(self, msg: HiveMessage) -> None:
        pass


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _make_pair():
    """Direction semantics:
        client posts   -> hub_secret  (wormhole polls with hub_secret)
        wormhole posts  -> my_secret  (client polls with my_secret)
    """
    transport  = _SharedFakeTransport()
    creds_c    = _RoundTripCreds("client")
    creds_h    = _RoundTripCreds("hub")

    carrier_c  = EmailCarrier(creds_c, transport)
    carrier_h  = EmailCarrier(creds_h, transport)

    hub_proto   = _FakeHmProtocol()
    slave_proto = _FakeSlaveProtocol()

    wormhole = EmailWormhole(
        config={
            "my_secret":    "client-to-hub",
            "peer_secret":  "hub-to-client",
            "peer_email":   "client@example.com",
            "peer_pubkey":  creds_c.pubkey,
            "poll_seconds": 99999,
        },
        hm_protocol=hub_proto,
    )
    wormhole._carrier       = carrier_h
    wormhole._carrier.creds = creds_h

    client = HiveMindEmailClient(
        config={
            "my_secret":  "hub-to-client",
            "hub_secret": "client-to-hub",
            "hub_email":  "hub@example.com",
            "hub_pubkey": creds_h.pubkey,
            "poll_seconds": 99999,
        },
        _carrier=carrier_c,
    )
    client._carrier       = carrier_c
    client._carrier.creds = creds_c

    client.protocol = slave_proto
    slave_proto.bind(None)
    client.connected.set()

    return client, wormhole, slave_proto, hub_proto, carrier_c, carrier_h


def _hub_poll_once(wormhole: EmailWormhole) -> None:
    my_secret = wormhole.config["my_secret"]
    messages  = wormhole._carrier.poll(my_secret)
    for kind, payload, _sender in messages:
        if kind == _KIND_HIVE:
            wormhole._dispatch(payload)


def _client_poll_once(client: HiveMindEmailClient) -> None:
    my_secret = client.config.get("my_secret", "")
    messages  = client._carrier.poll(my_secret)
    for kind, payload, _sender in messages:
        if kind == _KIND_HIVE:
            client._dispatch(payload)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestClientToHub:

    def test_single_message_reaches_hub(self):
        client, wormhole, slave_p, hub_p, cc, ch = _make_pair()

        original = HiveMessage(HiveMessageType.PING, payload={"hello": "world"})
        client.emit(original)

        _hub_poll_once(wormhole)

        assert len(hub_p.received) == 1
        assert hub_p.received[0].msg_type == HiveMessageType.PING

    def test_bus_message_context_enriched(self):
        client, wormhole, slave_p, hub_p, cc, ch = _make_pair()

        from ovos_bus_client import Message as MycroftMessage
        mycroft_msg = MycroftMessage("speak", {"utterance": "hi"})
        client.emit(mycroft_msg)

        _hub_poll_once(wormhole)

        assert len(hub_p.received) == 1
        received = hub_p.received[0]
        assert received.msg_type == HiveMessageType.BUS
        ctx = received.payload.context
        assert ctx.get("destination") == "HiveMind"
        assert ctx["session"]["session_id"] == client.session_id

    def test_large_message_chunked_and_reassembled(self):
        client, wormhole, slave_p, hub_p, cc, ch = _make_pair()

        big = HiveMessage(HiveMessageType.RENDEZVOUS,
                          payload={"blob": "X" * (CHUNK_SIZE * 3)})
        assert len(big.serialize().encode()) > CHUNK_SIZE

        client.emit(big)
        _hub_poll_once(wormhole)

        assert len(hub_p.received) == 1

    def test_byte_identical_payload_at_hub(self):
        client, wormhole, slave_p, hub_p, cc, ch = _make_pair()

        original = HiveMessage(HiveMessageType.QUERY,
                               payload={"utterance": "what time is it"})
        client.emit(original)
        _hub_poll_once(wormhole)

        assert len(hub_p.received) == 1
        received = hub_p.received[0]
        assert json.loads(received.serialize()) == json.loads(original.serialize())


class TestHubToClient:

    def test_hello_routed_to_slave_protocol(self):
        client, wormhole, slave_p, hub_p, cc, ch = _make_pair()

        hub_msg = HiveMessage(HiveMessageType.HELLO,
                              payload={"pubkey": "HUB-KEY", "node_id": "hub-001"})
        ch.send(hub_msg.serialize().encode(), to_addr="client@example.com",
                peer_secret=wormhole.config["peer_secret"],
                peer_pubkey=cc.creds.pubkey,
                kind=_KIND_HIVE)

        _client_poll_once(client)

        assert len(slave_p.received_hello) == 1
        assert slave_p.received_hello[0].msg_type == HiveMessageType.HELLO

    def test_broadcast_routed_to_slave_protocol(self):
        client, wormhole, slave_p, hub_p, cc, ch = _make_pair()

        hub_msg = HiveMessage(HiveMessageType.BROADCAST, payload={"data": 123})
        ch.send(hub_msg.serialize().encode(), to_addr="client@example.com",
                peer_secret=wormhole.config["peer_secret"],
                peer_pubkey=cc.creds.pubkey,
                kind=_KIND_HIVE)

        _client_poll_once(client)

        assert len(slave_p.received_broadcast) == 1

    def test_custom_handler_called(self):
        client, wormhole, slave_p, hub_p, cc, ch = _make_pair()

        received = []
        client.on(HiveMessageType.PING, received.append)

        hub_msg = HiveMessage(HiveMessageType.PING, payload={})
        ch.send(hub_msg.serialize().encode(), to_addr="client@example.com",
                peer_secret=wormhole.config["peer_secret"],
                peer_pubkey=cc.creds.pubkey,
                kind=_KIND_HIVE)

        _client_poll_once(client)

        assert len(received) == 1
        assert received[0].msg_type == HiveMessageType.PING

    def test_non_hive_kind_ignored(self):
        client, wormhole, slave_p, hub_p, cc, ch = _make_pair()

        ch.send(b"plain text", to_addr="client@example.com",
                peer_secret=wormhole.config["peer_secret"],
                peer_pubkey=cc.creds.pubkey,
                kind="nl")

        _client_poll_once(client)

        assert slave_p.received_hello      == []
        assert slave_p.received_handshake  == []
        assert slave_p.received_bus        == []


class TestClientLifecycle:

    def test_emit_before_connect_raises(self):
        client = HiveMindEmailClient(config={
            "my_secret":  "s1",
            "hub_secret": "s2",
            "hub_email":  "hub@example.com",
            "hub_pubkey": "KEY",
        })
        with pytest.raises(ConnectionAbortedError):
            client.emit(HiveMessage(HiveMessageType.PING, payload={}))

    def test_stop_event(self):
        client, *_ = _make_pair()
        client.close()
        assert client._stop_event.is_set()

    def test_on_mycroft_handler(self):
        client, wormhole, slave_p, hub_p, cc, ch = _make_pair()

        received_mycroft = []
        client.on_mycroft("speak", received_mycroft.append)

        from ovos_bus_client import Message as MycroftMessage
        inner = MycroftMessage("speak", {"utterance": "hello"})
        hub_msg = HiveMessage(HiveMessageType.BUS, payload=inner)

        ch.send(hub_msg.serialize().encode(), to_addr="client@example.com",
                peer_secret=wormhole.config["peer_secret"],
                peer_pubkey=cc.creds.pubkey,
                kind=_KIND_HIVE)

        _client_poll_once(client)

        assert len(received_mycroft) == 1
        assert received_mycroft[0].data["utterance"] == "hello"

    def test_remove_handler(self):
        client, wormhole, slave_p, hub_p, cc, ch = _make_pair()

        calls = []
        handler = calls.append
        client.on(HiveMessageType.PING, handler)
        client.remove(HiveMessageType.PING, handler)

        hub_msg = HiveMessage(HiveMessageType.PING, payload={})
        ch.send(hub_msg.serialize().encode(), to_addr="client@example.com",
                peer_secret=wormhole.config["peer_secret"],
                peer_pubkey=cc.creds.pubkey,
                kind=_KIND_HIVE)

        _client_poll_once(client)

        assert calls == []
