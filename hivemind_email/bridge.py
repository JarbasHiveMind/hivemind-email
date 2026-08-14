"""EmailBridge -- NL gateway between a mailbox and the HiveMind.

This is the "answers ALL users" surface, the email analogue of
``hivemind_usenet.bridge.UsenetBridge``: an open, public-facing
assistant-over-email. Any email that lands in the configured mailbox is
treated as a natural-language utterance from its sender, forwarded to the
hive, and the spoken reply is emailed back to that sender. By default there
is NO allowlist -- anyone who emails the bridge's address gets an answer,
exactly like anyone can post a question to the usenet bridge's code-word
hSub. An optional ``allowed_senders`` set can restrict this if the deployer
wants a private assistant instead of a public one.

Do not confuse this with ``EmailWormhole``: the wormhole carries encrypted
HiveMind wire-protocol frames between two specific nodes (peer-to-peer,
PGP-keyed). This bridge speaks plain natural language with anyone who
emails it and never touches HiveMessage framing.

BRIDGE-1 conformance (hivemind-ovos-bridge-conformance Sec5):
- ``context.source`` is stamped per *peer* (each distinct sender address).
- ``context.session`` carries a per-peer ``session_id`` that never collides
  with ``"default"`` (SESSION-1 Sec3.1).
- Per-session FIFO: a queue per session_id serialises processing; a
  dedicated worker thread drains each queue in order.
"""
import queue
import threading
from typing import Any, Callable, Dict, Optional, Set

from ovos_utils.log import LOG

from hivemind_bus_client.client import HiveMessageBusClient

from hivemind_email.carrier import SMTPIMAPTransport


# ---------------------------------------------------------------------------
# Session/FIFO helpers
# ---------------------------------------------------------------------------

class _SessionQueue:
    """FIFO queue for one session. Items are dicts (see _process_item)."""

    def __init__(self) -> None:
        self._q: queue.Queue = queue.Queue()
        self._worker: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self, handler: Callable) -> None:
        self._stop.clear()
        self._worker = threading.Thread(
            target=self._drain, args=(handler,), daemon=True
        )
        self._worker.start()

    def enqueue(self, item: Any) -> None:
        self._q.put(item)

    def stop(self) -> None:
        self._stop.set()
        self._q.put(None)  # unblock

    def _drain(self, handler: Callable) -> None:
        while not self._stop.is_set():
            try:
                item = self._q.get(timeout=1)
            except queue.Empty:
                continue
            if item is None:
                break
            try:
                handler(item)
            except Exception as exc:
                LOG.exception("EmailBridge: session handler error: %s", exc)


# ---------------------------------------------------------------------------
# EmailBridge
# ---------------------------------------------------------------------------

class EmailBridge(threading.Thread):
    """Natural-language bridge: inbound email -> hive utterance -> email reply.

    Parameters (all passed as constructor kwargs):
        transport        - SMTPIMAPTransport (or compatible stub) handling
                            send()/poll() against the bridge's mailbox.
        hive_host        - HiveMind server host.
        hive_port        - HiveMind server port (default 5678).
        hive_key         - API key for HiveMind connection.
        from_addr        - The bridge's own email address (used to skip
                            its own outgoing mail if it ever shows back up,
                            and as the From: on replies).
        poll_seconds     - Poll cadence (default 30).
        poll_limit       - Mails per poll (default 200).
        allowed_senders  - Optional set of sender addresses to allowlist;
                            None (default) = answer EVERYONE who emails in.
    """

    def __init__(
        self,
        transport,
        hive_host:       str = "127.0.0.1",
        hive_port:       int = 5678,
        hive_key:        str = "",
        from_addr:       str = "",
        poll_seconds:    int = 30,
        poll_limit:      int = 200,
        allowed_senders: Optional[Set[str]] = None,
        **kwargs,
    ) -> None:
        super().__init__(daemon=True, **kwargs)
        self.transport       = transport
        self.hive_host       = hive_host
        self.hive_port       = hive_port
        self.hive_key        = hive_key
        self.from_addr       = (from_addr or getattr(transport, "from_addr", "")).lower()
        self.poll_seconds    = poll_seconds
        self.poll_limit      = poll_limit
        self.allowed_senders = allowed_senders

        self._stop = threading.Event()
        self._connected = threading.Event()

        # per-session FIFO queues: session_id -> _SessionQueue
        self._sessions: Dict[str, _SessionQueue] = {}
        self._sessions_lock = threading.Lock()

        # HiveMind client (lazy)
        self._hm_client: Optional[HiveMessageBusClient] = None

    # ------------------------------------------------------------------
    # HiveMind client (lazy)
    # ------------------------------------------------------------------

    def _get_hm_client(self) -> HiveMessageBusClient:
        if self._hm_client is None:
            self._hm_client = HiveMessageBusClient(
                key=self.hive_key,
                host=self.hive_host,
                port=self.hive_port,
            )
            self._hm_client.connect()
            self._connected.set()
        return self._hm_client

    # ------------------------------------------------------------------
    # Session helpers (BRIDGE-1 Sec5 FIFO)
    # ------------------------------------------------------------------

    def _session_id(self, peer_email: str) -> str:
        """Stable per-peer session id that never equals 'default'."""
        return f"email-bridge-{peer_email}"

    def _get_session_queue(self, session_id: str) -> _SessionQueue:
        with self._sessions_lock:
            if session_id not in self._sessions:
                sq = _SessionQueue()
                sq.start(self._process_item)
                self._sessions[session_id] = sq
            return self._sessions[session_id]

    # ------------------------------------------------------------------
    # Processing
    # ------------------------------------------------------------------

    def _process_item(self, item: Dict) -> None:
        text       = item["text"]
        peer_email = item["peer_email"]
        subject    = item["subject"]
        session_id = item["session_id"]

        LOG.info("EmailBridge: query from %s: %s", peer_email, text[:80])

        try:
            client = self._get_hm_client()
            response_text = client.ask(
                text,
                context={
                    "source":      peer_email,
                    "destination": peer_email,
                    "session_id":  session_id,
                },
            )
        except Exception as exc:
            LOG.exception("EmailBridge: hive query error: %s", exc)
            response_text = "Sorry, something went wrong processing your request."

        try:
            reply_subject = subject if subject.lower().startswith("re:") else f"Re: {subject}"
            self.transport.send(peer_email, reply_subject, response_text)
        except Exception as exc:
            LOG.exception("EmailBridge: reply error: %s", exc)

    # ------------------------------------------------------------------
    # Inbound polling
    # ------------------------------------------------------------------

    def _handle_mail(self, subject: str, text: str, peer_email: str) -> None:
        text = (text or "").strip()
        if not text:
            return

        peer_email = (peer_email or "").lower()
        if not peer_email:
            LOG.debug("EmailBridge: mail with no sender address, dropping")
            return

        # never answer our own mail
        if self.from_addr and peer_email == self.from_addr:
            return

        if self.allowed_senders is not None and peer_email not in self.allowed_senders:
            LOG.debug("EmailBridge: ignoring sender %s (not in allowlist)", peer_email)
            return

        session_id = self._session_id(peer_email)
        sq         = self._get_session_queue(session_id)
        sq.enqueue({
            "text":       text,
            "peer_email": peer_email,
            "subject":    subject or "HiveMind",
            "session_id": session_id,
        })

    def _poll_once(self) -> None:
        mails = self.transport.poll(limit=self.poll_limit)
        for mail in mails:
            subject = getattr(mail, "subject", "") or ""
            text    = getattr(mail, "text", "") or ""
            sender  = getattr(mail, "sender", "") or ""
            self._handle_mail(subject, text, sender)

    # ------------------------------------------------------------------
    # Thread entry-point
    # ------------------------------------------------------------------

    def run(self) -> None:
        LOG.info("EmailBridge: starting poll loop (interval=%ds)", self.poll_seconds)
        while not self._stop.is_set():
            try:
                self._poll_once()
            except Exception as exc:
                LOG.exception("EmailBridge: poll error: %s", exc)
            self._stop.wait(self.poll_seconds)
        LOG.info("EmailBridge: stopped")

    def stop(self) -> None:
        self._stop.set()
        with self._sessions_lock:
            for sq in self._sessions.values():
                sq.stop()


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="HiveMind Email NL Bridge (answers all senders)")
    parser.add_argument("--imap-host",     required=True)
    parser.add_argument("--imap-user",     required=True)
    parser.add_argument("--imap-password", required=True)
    parser.add_argument("--imap-port",     type=int, default=993)
    parser.add_argument("--smtp-host",     default=None, help="defaults to --imap-host")
    parser.add_argument("--smtp-user",     default=None, help="defaults to --imap-user")
    parser.add_argument("--smtp-password", default=None, help="defaults to --imap-password")
    parser.add_argument("--smtp-port",     type=int, default=465)
    parser.add_argument("--folder",        default="inbox")
    parser.add_argument("--hive-host",     default="127.0.0.1")
    parser.add_argument("--hive-port",     type=int, default=5678)
    parser.add_argument("--hive-key",      default="")
    parser.add_argument("--poll-seconds",  type=int, default=30)
    parser.add_argument("--allowed-senders", default=None,
                         help="Comma-separated allowlist; omit to answer everyone")
    args = parser.parse_args()

    transport = SMTPIMAPTransport(
        smtp_host     = args.smtp_host or args.imap_host,
        smtp_user     = args.smtp_user or args.imap_user,
        smtp_password = args.smtp_password or args.imap_password,
        smtp_port     = args.smtp_port,
        imap_host     = args.imap_host,
        imap_user     = args.imap_user,
        imap_password = args.imap_password,
        imap_port     = args.imap_port,
        folder        = args.folder,
    )

    allowed = None
    if args.allowed_senders:
        allowed = {a.strip().lower() for a in args.allowed_senders.split(",") if a.strip()}

    bridge = EmailBridge(
        transport       = transport,
        hive_host       = args.hive_host,
        hive_port       = args.hive_port,
        hive_key        = args.hive_key,
        poll_seconds    = args.poll_seconds,
        allowed_senders = allowed,
    )
    bridge.start()
    bridge.join()
