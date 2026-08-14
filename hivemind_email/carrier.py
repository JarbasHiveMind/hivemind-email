"""EmailCarrier — shared framing layer for HiveMind-over-email.

Splits arbitrary-size payloads into ~8 KB base64 chunks, PGP-encrypts each
chunk to the peer's public key, sends them as emails via SMTP with the
subject stamped by an hSub passphrase, then reassembles complete messages by
polling a mailbox over IMAP.  Fully unit-testable without a live SMTP/IMAP
connection: inject a stub ``EmailTransport``.

This mirrors ``hivemind_usenet.carrier.UsenetCarrier`` chunk-for-chunk; the
only thing that changes is the transport (SMTP/IMAP instead of NNTP) and
that a frame is addressed to a specific recipient email instead of posted
to a shared newsgroup.
"""
import base64
import json
import smtplib
import uuid
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from typing import Dict, List, Optional, Set, Tuple

from remailers import create_hsub, match_hsub
from remailers.keys import Credentials

CHUNK_SIZE = 6_000          # bytes of raw payload per chunk (b64 ~= 8 KB)
CARRIER_VERSION = 1
_KIND_HIVE = "hive"
_KIND_NL   = "nl"
VALID_KINDS = {_KIND_HIVE, _KIND_NL}


# ---------------------------------------------------------------------------
# Frame dataclass (identical wire format to hivemind_usenet.carrier.Frame)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Frame:
    """A single email's logical payload, before/after base64."""
    v:    int          # carrier version
    mid:  str          # message-id (UUID4) - groups chunks of one logical msg
    seq:  int          # 0-based chunk index
    n:    int          # total chunk count
    kind: str          # "hive" | "nl"
    data: str          # base64-encoded chunk

    def to_json(self) -> str:
        return json.dumps({
            "v":    self.v,
            "mid":  self.mid,
            "seq":  self.seq,
            "n":    self.n,
            "kind": self.kind,
            "data": self.data,
        })

    @classmethod
    def from_json(cls, text: str) -> "Frame":
        d = json.loads(text)
        return cls(
            v=int(d["v"]),
            mid=str(d["mid"]),
            seq=int(d["seq"]),
            n=int(d["n"]),
            kind=str(d["kind"]),
            data=str(d["data"]),
        )


# ---------------------------------------------------------------------------
# Reassembly buffer (identical logic to hivemind_usenet.carrier)
# ---------------------------------------------------------------------------

@dataclass
class _MessageBuffer:
    n:      int
    chunks: Dict[int, bytes] = field(default_factory=dict)
    kind:   Optional[str]    = None
    sender: str              = ""

    def add(self, frame: Frame, sender: str = "") -> None:
        self.chunks[frame.seq] = base64.b64decode(frame.data)
        self.kind = frame.kind
        if sender:
            self.sender = sender

    def complete(self) -> bool:
        return len(self.chunks) == self.n

    def reassemble(self) -> bytes:
        return b"".join(self.chunks[i] for i in range(self.n))


class CarrierBuffer:
    """Holds partial messages across multiple poll() calls.

    Thread-safety: not reentrant; callers must serialise if needed.
    """

    def __init__(self) -> None:
        self._buffers: Dict[str, _MessageBuffer] = {}
        self._seen:    Set[Tuple[str, int]]       = set()     # (mid, seq) dedup

    def ingest(self, frame: Frame, sender: str = "") -> Optional[Tuple[str, bytes, str]]:
        """Add *frame*; return (kind, payload, sender) when the message is complete.

        Returns None if the message is still incomplete or was already seen.
        Duplicate (mid, seq) pairs are silently dropped. ``sender`` is the
        email address the frame arrived from (best-effort, carried across
        chunks of the same logical message).
        """
        key = (frame.mid, frame.seq)
        if key in self._seen:
            return None
        self._seen.add(key)

        if frame.mid not in self._buffers:
            self._buffers[frame.mid] = _MessageBuffer(n=frame.n)
        buf = self._buffers[frame.mid]
        buf.add(frame, sender)
        if buf.complete():
            payload = buf.reassemble()
            kind    = buf.kind
            who     = buf.sender
            del self._buffers[frame.mid]
            return kind, payload, who
        return None


# ---------------------------------------------------------------------------
# EmailTransport — pluggable SMTP (send) + IMAP (poll) backend
# ---------------------------------------------------------------------------

@dataclass
class EmailMessage:
    """Minimal shape the carrier needs from an inbound email."""
    subject: str
    text:    str
    sender:  str = ""


class SMTPIMAPTransport:
    """Default live transport: sends via smtplib, polls via mail_monitor.

    Only imported/instantiated when actually used (live network path); the
    offline test-suite injects a stub transport instead.
    """

    def __init__(
        self,
        smtp_host: str,
        smtp_user: str,
        smtp_password: str,
        imap_host: str,
        imap_user: str,
        imap_password: str,
        smtp_port: int = 465,
        imap_port: int = 993,
        from_addr: Optional[str] = None,
        folder: str = "inbox",
    ) -> None:
        self.smtp_host     = smtp_host
        self.smtp_port     = smtp_port
        self.smtp_user     = smtp_user
        self.smtp_password = smtp_password
        self.from_addr     = from_addr or smtp_user
        self.imap_host     = imap_host
        self.imap_port     = imap_port
        self.imap_user     = imap_user
        self.imap_password = imap_password
        self.folder        = folder

        from mail_monitor import EmailClient
        self._imap = EmailClient(imap_user, imap_password, address=imap_host,
                                  port=imap_port, folder=folder)

    def send(self, to_addr: str, subject: str, body: str) -> None:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"]    = self.from_addr
        msg["To"]      = to_addr
        with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port) as s:
            s.login(self.smtp_user, self.smtp_password)
            s.sendmail(self.from_addr, [to_addr], msg.as_string())

    def poll(self, limit: int = 200) -> List[EmailMessage]:
        mails = self._imap.list_new_emails(mark_as_seen=True)
        out = [
            EmailMessage(subject=m.get("subject", ""), text=m.get("payload", ""),
                         sender=m.get("email", ""))
            for m in mails
        ]
        return out[:limit]


# ---------------------------------------------------------------------------
# EmailCarrier
# ---------------------------------------------------------------------------

class EmailCarrier:
    """Frame, encrypt, send, receive, decrypt, reassemble HiveMind payloads.

    Parameters
    ----------
    creds:
        Local ``Credentials`` (RSA-4096 PGP key). Decryption uses the
        private key; encryption uses the *peer*'s public key passed per call.
    transport:
        An ``EmailTransport`` (or compatible stub/``SMTPIMAPTransport``).
        The carrier calls ``transport.send(to_addr, subject, body)`` and
        ``transport.poll(limit)``.
    chunk_size:
        Maximum raw bytes per chunk (before base64). Default 6 000.
    """

    def __init__(
        self,
        creds:      Credentials,
        transport,                       # EmailTransport-compatible
        chunk_size: int = CHUNK_SIZE,
    ) -> None:
        self.creds      = creds
        self.transport  = transport
        self.chunk_size = chunk_size
        self._buf       = CarrierBuffer()

    # ------------------------------------------------------------------
    # Send path
    # ------------------------------------------------------------------

    def send(
        self,
        payload:     bytes,
        to_addr:     str,
        peer_secret: str,
        peer_pubkey: str,
        kind:        str = _KIND_HIVE,
    ) -> None:
        """Chunk *payload*, PGP-encrypt each frame, and email it to *to_addr*.

        Parameters
        ----------
        payload:
            Raw bytes to transmit.
        to_addr:
            Recipient email address.
        peer_secret:
            Shared passphrase used to create an hSub subject (receiver can
            match it with ``match_hsub(subject, peer_secret)``).
        peer_pubkey:
            ASCII-armored PGP public key of the receiver.
        kind:
            ``"hive"`` (wormhole) or ``"nl"`` (bridge).
        """
        if kind not in VALID_KINDS:
            raise ValueError(f"Invalid kind: {kind!r}")

        chunks = [
            payload[i : i + self.chunk_size]
            for i in range(0, max(len(payload), 1), self.chunk_size)
        ]
        mid = str(uuid.uuid4())
        n   = len(chunks)

        for seq, chunk in enumerate(chunks):
            frame = Frame(
                v    = CARRIER_VERSION,
                mid  = mid,
                seq  = seq,
                n    = n,
                kind = kind,
                data = base64.b64encode(chunk).decode(),
            )
            ciphertext = self.creds.encrypt(frame.to_json(), peer_pubkey)
            subject    = create_hsub(peer_secret)
            self.transport.send(to_addr, subject, ciphertext)

    # ------------------------------------------------------------------
    # Receive path
    # ------------------------------------------------------------------

    def poll(
        self,
        my_secret: str,
        limit:     int = 200,
    ) -> List[Tuple[str, bytes, str]]:
        """Scan the mailbox, decrypt matching mails, reassemble, return complete messages.

        Parameters
        ----------
        my_secret:
            Shared passphrase used to match hSub subjects.
        limit:
            How many recent mails to fetch per call.

        Returns
        -------
        List of ``(kind, payload, sender)`` tuples for every newly completed
        message. ``sender`` is the From: address of the (last-seen chunk of
        the) email, best-effort.
        """
        try:
            mails = self.transport.poll(limit=limit)
        except Exception:
            return []

        results: List[Tuple[str, bytes, str]] = []

        for mail in mails:
            subject = getattr(mail, "subject", "") or ""
            if not match_hsub(subject, my_secret):
                continue

            body = getattr(mail, "text", "") or ""
            if not body.strip():
                continue

            sender = getattr(mail, "sender", "") or ""

            try:
                plaintext = self.creds.decrypt(body)
            except Exception:
                continue

            try:
                frame = Frame.from_json(plaintext)
            except Exception:
                continue

            result = self._buf.ingest(frame, sender=sender)
            if result is not None:
                results.append(result)

        return results
