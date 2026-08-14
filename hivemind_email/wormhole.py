"""EmailWormhole -- NetworkProtocol that tunnels HiveMessage objects over email.

Each instance manages ONE point-to-point link:

    local-node  <---->  EmailCarrier  <---->  peer-node
                (hSub subject + PGP, SMTP/IMAP)

This is the PROTOCOL surface, not the NL bridge: it does not "answer users".
It carries the actual HiveMind wire protocol (HiveMessage frames) between two
specific nodes, keyed to one peer's PGP key and email address -- exactly the
email analogue of ``hivemind_usenet.wormhole.UsenetWormhole``, which routes
kind="hive" frames into ``hm_protocol.handle_message``.

Inbound frames with kind="hive" are deserialized and routed to
``hm_protocol.handle_message(msg, client)``.  The matching
``HiveMindClientConnection.send_msg`` callback sends outbound frames back
via the carrier, addressed to the configured peer email.

Config keys (all passed in ``self.config``):
    my_secret     (str)  - hSub passphrase we read with
    peer_secret   (str)  - hSub passphrase we post with (peer reads this)
    peer_email    (str)  - the peer's email address (SMTP recipient)
    peer_pubkey   (str)  - ASCII-armored PGP public key of the peer
    key_path      (str)  - path for local Credentials auto-generation
    smtp_host/user/password/port
    imap_host/user/password/port
    folder        (str)  - IMAP folder to poll (default: inbox)
    poll_seconds  (int)  - poll cadence          (default: 60)
    poll_limit    (int)  - mails per poll        (default: 200)
"""
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ovos_utils.log import LOG

from hivemind_bus_client.message import HiveMessage
from hivemind_plugin_manager.protocols import NetworkProtocol
from hivemind_core.protocol import HiveMindClientConnection

from remailers.keys import Credentials

from hivemind_email.carrier import EmailCarrier, SMTPIMAPTransport, _KIND_HIVE


# ---------------------------------------------------------------------------
# Synthetic HiveMindClientConnection for this peer
# ---------------------------------------------------------------------------

def _make_client_connection(peer_id: str, carrier: EmailCarrier, peer_email: str,
                             peer_secret: str, peer_pubkey: str,
                             hm_protocol=None) -> HiveMindClientConnection:
    """Build a minimal HiveMindClientConnection whose send_msg emails via carrier."""

    def _send(msg: HiveMessage) -> None:
        data = msg.serialize().encode()
        carrier.send(data, to_addr=peer_email, peer_secret=peer_secret,
                     peer_pubkey=peer_pubkey, kind=_KIND_HIVE)

    def _disconnect() -> None:
        LOG.debug(f"EmailWormhole: peer disconnected: {peer_id}")

    return HiveMindClientConnection(
        key         = peer_id,
        send_msg    = _send,
        disconnect  = _disconnect,
        hm_protocol = hm_protocol,
    )


# ---------------------------------------------------------------------------
# EmailWormhole
# ---------------------------------------------------------------------------

@dataclass
class EmailWormhole(NetworkProtocol):
    """NetworkProtocol that transports full HiveMessage objects over email.

    Entry-point: ``hivemind.network.protocol``
    Name:        ``hivemind-email-wormhole``
    """

    config:      Dict[str, Any] = field(default_factory=dict)
    _carrier:    Optional[EmailCarrier]              = field(default=None, init=False, repr=False)
    _client_conn:Optional[HiveMindClientConnection]  = field(default=None, init=False, repr=False)
    _stop_event: threading.Event                     = field(default_factory=threading.Event, init=False, repr=False)

    # ------------------------------------------------------------------
    # Setup helpers
    # ------------------------------------------------------------------

    def _build_carrier(self) -> EmailCarrier:
        key_path = self.config.get("key_path", "/tmp/hivemind_email_wormhole.asc")
        creds    = Credentials(key_path)
        transport = SMTPIMAPTransport(
            smtp_host     = self.config["smtp_host"],
            smtp_user     = self.config["smtp_user"],
            smtp_password = self.config["smtp_password"],
            imap_host     = self.config.get("imap_host", self.config["smtp_host"]),
            imap_user     = self.config.get("imap_user", self.config["smtp_user"]),
            imap_password = self.config.get("imap_password", self.config["smtp_password"]),
            smtp_port     = int(self.config.get("smtp_port", 465)),
            imap_port     = int(self.config.get("imap_port", 993)),
            folder        = self.config.get("folder", "inbox"),
        )
        return EmailCarrier(creds, transport)

    def _ensure_client(self, carrier: EmailCarrier) -> HiveMindClientConnection:
        if self._client_conn is not None:
            return self._client_conn
        peer_id     = self.config.get("peer_id", "email-peer")
        peer_email  = self.config["peer_email"]
        peer_secret = self.config["peer_secret"]
        peer_pubkey = self.config["peer_pubkey"]
        self._client_conn = _make_client_connection(
            peer_id, carrier, peer_email, peer_secret, peer_pubkey,
            hm_protocol=self.hm_protocol,
        )
        if self.hm_protocol:
            self.callbacks.on_connect(self._client_conn)
        return self._client_conn

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Block, poll the mailbox, dispatch inbound HiveMessages."""
        poll_seconds = int(self.config.get("poll_seconds", 60))
        poll_limit   = int(self.config.get("poll_limit", 200))
        my_secret    = self.config["my_secret"]

        self._carrier = self._build_carrier()
        self._stop_event.clear()

        LOG.info("EmailWormhole: starting poll loop (interval=%ds)", poll_seconds)
        while not self._stop_event.is_set():
            try:
                messages = self._carrier.poll(my_secret, limit=poll_limit)
                for kind, payload, _sender in messages:
                    if kind != _KIND_HIVE:
                        continue
                    self._dispatch(payload)
            except Exception as exc:
                LOG.exception("EmailWormhole: poll error: %s", exc)

            self._stop_event.wait(poll_seconds)

        LOG.info("EmailWormhole: stopped")

    def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, payload: bytes) -> None:
        try:
            msg = HiveMessage.deserialize(payload.decode())
        except Exception as exc:
            LOG.warning("EmailWormhole: failed to deserialize HiveMessage: %s", exc)
            return

        if not self.hm_protocol:
            LOG.warning("EmailWormhole: no hm_protocol; dropping message")
            return

        client = self._ensure_client(self._carrier)
        try:
            self.hm_protocol.handle_message(msg, client)
        except Exception as exc:
            LOG.exception("EmailWormhole: handle_message error: %s", exc)


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse, json as _json

    parser = argparse.ArgumentParser(description="HiveMind Email Wormhole (protocol transport)")
    parser.add_argument("--config", default=None, help="Path to JSON config file")
    parser.add_argument("--my-secret",     default=None, help="hSub passphrase we read with")
    parser.add_argument("--peer-secret",   default=None, help="hSub passphrase we post with")
    parser.add_argument("--peer-email",    default=None, help="Peer's email address")
    parser.add_argument("--peer-pubkey",   default=None, help="Path to ASCII-armored peer public key file")
    parser.add_argument("--key-path",      default=None)
    parser.add_argument("--smtp-host",     default=None)
    parser.add_argument("--smtp-user",     default=None)
    parser.add_argument("--smtp-password", default=None)
    parser.add_argument("--smtp-port",     type=int, default=465)
    parser.add_argument("--imap-host",     default=None)
    parser.add_argument("--imap-user",     default=None)
    parser.add_argument("--imap-password", default=None)
    parser.add_argument("--imap-port",     type=int, default=993)
    parser.add_argument("--folder",        default="inbox")
    parser.add_argument("--poll-seconds",  type=int, default=60)
    args = parser.parse_args()

    cfg: Dict[str, Any] = {}
    if args.config:
        with open(args.config) as fh:
            cfg = _json.load(fh)

    for k in ("my_secret", "peer_secret", "peer_email", "key_path",
              "smtp_host", "smtp_user", "smtp_password", "imap_host",
              "imap_user", "imap_password", "folder"):
        v = getattr(args, k)
        if v:
            cfg[k] = v
    cfg["smtp_port"]    = args.smtp_port
    cfg["imap_port"]    = args.imap_port
    cfg["poll_seconds"] = args.poll_seconds

    if args.peer_pubkey:
        with open(args.peer_pubkey) as fh:
            cfg["peer_pubkey"] = fh.read()

    wormhole = EmailWormhole(config=cfg)
    wormhole.run()
