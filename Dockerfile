FROM python:3.14-slim

WORKDIR /app
COPY . /app

# force the current hivemind-bus-client alpha rather than whatever a stale
# base layer might already have cached
RUN pip install --no-cache-dir --upgrade "hivemind-bus-client>=1.0.13a1" \
    && pip install --no-cache-dir --pre .

# credentials are passed as environment variables at `docker run` / compose
# time, never baked into the image. MODE selects which console script runs:
#   MODE=bridge   -> hivemind-email-bridge   (answers all senders, plaintext NL)
#   MODE=wormhole -> hivemind-email-wormhole (peer-to-peer, PGP protocol transport)
ENV MODE=bridge \
    IMAP_PORT=993 \
    SMTP_PORT=465 \
    FOLDER=inbox \
    HIVEMIND_HOST=127.0.0.1 \
    HIVEMIND_PORT=5678 \
    POLL_SECONDS=30

ENTRYPOINT ["sh", "-c", "\
  if [ \"$MODE\" = \"wormhole\" ]; then \
    exec hivemind-email-wormhole \
      --my-secret \"$MY_SECRET\" \
      --peer-secret \"$PEER_SECRET\" \
      --peer-email \"$PEER_EMAIL\" \
      --peer-pubkey \"$PEER_PUBKEY_PATH\" \
      --key-path \"$KEY_PATH\" \
      --smtp-host \"$SMTP_HOST\" --smtp-user \"$SMTP_USER\" --smtp-password \"$SMTP_PASSWORD\" --smtp-port \"$SMTP_PORT\" \
      --imap-host \"$IMAP_HOST\" --imap-user \"$IMAP_USER\" --imap-password \"$IMAP_PASSWORD\" --imap-port \"$IMAP_PORT\" \
      --folder \"$FOLDER\" --poll-seconds \"$POLL_SECONDS\" $EXTRA_ARGS; \
  else \
    exec hivemind-email-bridge \
      --imap-host \"$IMAP_HOST\" --imap-user \"$IMAP_USER\" --imap-password \"$IMAP_PASSWORD\" --imap-port \"$IMAP_PORT\" \
      --smtp-host \"$SMTP_HOST\" --smtp-user \"$SMTP_USER\" --smtp-password \"$SMTP_PASSWORD\" --smtp-port \"$SMTP_PORT\" \
      --folder \"$FOLDER\" \
      --hive-host \"$HIVEMIND_HOST\" --hive-port \"$HIVEMIND_PORT\" --hive-key \"$HIVEMIND_ACCESS_KEY\" \
      --poll-seconds \"$POLL_SECONDS\" ${ALLOWED_SENDERS:+--allowed-senders \"$ALLOWED_SENDERS\"} $EXTRA_ARGS; \
  fi"]
