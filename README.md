# hivemind-email

A [HiveMind](https://github.com/JarbasHiveMind/HiveMind-core) transport over
**email**: store-and-forward mesh links carried by ordinary SMTP/IMAP
mailboxes. It ships two clearly separate surfaces in one package, mirroring
[hivemind-usenet](https://github.com/JarbasHiveMind/hivemind-usenet)'s
structure but swapping the carrier for email:

- **`EmailWormhole`** -- the PROTOCOL surface. A `NetworkProtocol` that
  carries encrypted HiveMind wire-protocol frames (`HiveMessage` objects)
  between two specific nodes. Peer-to-peer, PGP-keyed, and it is NOT natural
  language: it never "answers" anyone, it just relays the actual HiveMind
  handshake and bus traffic over email, exactly like `UsenetWormhole` routes
  `kind="hive"` frames into `hm_protocol.handle_message`.
- **`EmailBridge`** -- the NATURAL-LANGUAGE surface. A `threading.Thread`
  that turns a mailbox into an open, public-facing assistant: any email that
  lands in the inbox is treated as an utterance from its sender, forwarded to
  the hive, and the spoken reply is emailed back to that sender. By default
  there is **no allowlist** -- anyone who emails the bridge gets an answer,
  the same way anyone can post a question to the usenet bridge's code-word
  hSub. An optional `--allowed-senders` flag turns it into a private
  assistant if you want that instead.

Do not confuse the two: the wormhole is a protocol transport bound to one
peer's PGP key; the bridge is an open NL gateway that talks to everyone who
writes in.

A satellite-side client (`HiveMindEmailClient`) mirrors the HTTP/WS client
API, so the same connect/emit/run/close usage works over the email carrier.

## How it works

```
local node  <---- EmailCarrier (PGP + hSub subject, SMTP/IMAP) ---->  peer node
                 send an email to the peer's address
                 poll the mailbox, match hSub, decrypt, reassemble
```

- **`EmailCarrier`** is the shared framing layer both `EmailWormhole` and
  `EmailBridge`'s encrypted mode build on. It chunks arbitrary payloads into
  roughly 8 KB base64 frames, PGP-encrypts each to the peer's key, emails it
  with the subject stamped by `create_hsub(peer_secret)`, and reassembles
  complete messages by polling a mailbox over IMAP (`imaplib`, standard
  library).
- **Addressing** for the wormhole is hSub (hashed subject) plus a real
  recipient email address: a shared passphrase per peer, exchanged out of
  band together with PGP public keys.
- **The bridge does not use hSub or PGP for inbound mail** -- it answers
  whatever lands in its inbox in plaintext, because it is meant to be usable
  by anyone with an email client, not just peers who did a PGP key exchange.
- **Confidentiality** on the wormhole is PGP: each frame is encrypted to the
  peer's public key. **Reassembly** dedupes on `(message-id, chunk)` and
  rebuilds the payload once all chunks arrive -- identical logic to
  `hivemind-usenet`'s carrier.

## Prerequisites

- Python 3.10-3.12. The carrier's PGP crypto (`remailers` -> PGPy) imports
  the standard-library `imghdr` module, removed in Python 3.13 (PEP 594).
  The package is capped `>=3.10,<3.13`.
- A mailbox with IMAP and SMTP access. Any provider works. For Gmail, create
  an [app password](https://myaccount.google.com/apppasswords) -- do not use
  your normal account password, and enable IMAP access in Gmail settings.
- For the wormhole only: a PGP identity per node (`remailers.Credentials`
  generates one automatically at the configured `key_path` if missing), plus
  an out-of-band exchange of an **hSub passphrase** and the peer's **PGP
  public key** with the other node.
- For the bridge: nothing beyond the mailbox itself -- it is meant to be
  reachable by anyone.

## Install

```bash
pip install hivemind-email
```

From source:

```bash
git clone https://github.com/JarbasHiveMind/hivemind-email
cd hivemind-email
pip install -e .
```

## Quickstart

### Open NL assistant over email (`EmailBridge`)

Point it at a mailbox and a running `hivemind-core` hub. Anyone who emails
that mailbox gets an answer from the hive:

```bash
hivemind-email-bridge \
    --imap-host imap.gmail.com --imap-user assistant@example.com --imap-password "app-password" \
    --smtp-host smtp.gmail.com \
    --hive-host 127.0.0.1 --hive-key "my-hivemind-api-key" --hive-password "my-hivemind-password"
```

`--hive-key` is the access key and `--hive-password` is the Noise PSK
password -- both are required to authenticate against a v3-Noise-only
HiveMind hub. The legacy `crypto_key` is not used for authentication.

Add `--allowed-senders "a@example.com,b@example.com"` if you want a private
assistant instead of a public one. With no `--allowed-senders`, the bridge
answers ANY sender and logs a startup warning saying so.

For personal remote control of your own hive, pair the allowlist with a
subject token as a second factor -- sender addresses can be spoofed, so the
allowlist alone only stops casual abuse:

```bash
hivemind-email-bridge \
    --imap-host imap.gmail.com --imap-user assistant@example.com --imap-password "app-password" \
    --smtp-host smtp.gmail.com \
    --hive-host 127.0.0.1 --hive-key "my-hivemind-api-key" --hive-password "my-hivemind-password" \
    --allowed-senders "me@example.com" \
    --subject-token "correct-horse-battery-staple"
```

Every email must then come from an allowlisted address AND have a Subject
containing the token (case-insensitive substring match) to be processed.
`--required-subject` works the same way and can be combined with
`--subject-token`; when both are set, both must match. `--max-body-size`
(default 16384 characters) rejects oversized bodies before they reach the
hive. None of this is cryptographic sender authentication -- it is
defense-in-depth for a mailbox you already trust; real signing is future
work.

### Peer-to-peer protocol transport (`EmailWormhole`)

Two nodes that have exchanged passphrases and public keys out of band:

```bash
hivemind-email-wormhole \
    --my-secret   "my-passphrase" \
    --peer-secret "their-passphrase" \
    --peer-email  "peer@example.com" \
    --peer-pubkey /path/to/peer.asc \
    --imap-host imap.gmail.com --imap-user node-a@example.com --imap-password "app-password" \
    --smtp-host smtp.gmail.com
```

`--my-secret` is the hSub passphrase you **read** with. `--peer-secret` is
the one you **post** with, and the peer reads it. They are the mirror image
on the other node.

### Satellite client (`HiveMindEmailClient`)

```python
from hivemind_email.client import HiveMindEmailClient

client = HiveMindEmailClient(
    my_secret="hub-to-client",
    hub_secret="client-to-hub",
    hub_email="hub@example.com",
    hub_pubkey=open("hub.asc").read(),
    smtp_host="smtp.gmail.com", smtp_user="me@example.com", smtp_password="app-password",
)
client.connect()
client.start()
```

## First contact / hSub addressing (wormhole only)

hSub addressing is **shared-secret symmetric**: both peers must agree on a
passphrase and exchange PGP public keys out of band before any post. There
is no in-band key exchange. This only applies to `EmailWormhole`; the
`EmailBridge` needs no prior exchange since it deliberately talks to
strangers.

## Docker

```bash
cp .env.example .env   # fill in mailbox + hive credentials
docker compose up hivemind-email-bridge
# or, for the peer-to-peer transport:
docker compose --profile wormhole up hivemind-email-wormhole
```

See [`docker-compose.yml`](docker-compose.yml) and [`Dockerfile`](Dockerfile).

## Tests

All tests run **offline**. There is no live mailbox and no network. The
carrier's SMTP/IMAP transport is the only thing faked -- chunking, PGP, hSub
matching, and reassembly are all real:

```bash
uv venv --python 3.12
uv pip install --prerelease=allow -e .[test]
uv run pytest tests/
```

## Related projects

- [HiveMind-core](https://github.com/JarbasHiveMind/HiveMind-core): the hub
  this transport connects to.
- [hivemind-usenet](https://github.com/JarbasHiveMind/hivemind-usenet): the
  structural template this package follows, with Usenet instead of email as
  the carrier.
- [remailers](https://github.com/TigreGotico/remailers): the PGP identity
  and hSub-subject layer reused for the encrypted transport framing.

## License

Apache-2.0
