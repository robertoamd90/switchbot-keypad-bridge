# Keypad Touch 3.1 GCM beta

Select `keypad_crypto_mode: gcm` under `switchbot_keypad_bridge`.
Set `gcm_lock_slot_test: false` and keep the existing entities and
on_unlock/on_lock automations.

The standalone mode supports fingerprint, PIN, NFC and Lock.
The provisioning wizard still uses CTR. A keypad requiring GCM
during provisioning is unsupported. The current jolly was previously
provisioned successfully through this wizard. If its physical target
has changed back to the native lock, Reset the bridge, refresh the
wizard and associate once again.

Each connection receives a fresh random nonce. New requests advance
the counter. Replies use the nonce of the corresponding request,
as verified in the native captures. An exact duplicate of the last
request receives the cached response ciphertext, without repeating
the action. Invalid tags, unexpected commands and stale counters
invalidate the exchange. A session allows one action and up to
sixteen state polls within ten seconds.

A completed action emits one existing event after the verified poll
and disconnect. Method and index follow the existing event API.
Final state replies represent locked or unlocked state. Unknown
mechanical telemetry fields retain representative captured constants;
their full semantics are not established.

## Verification and limitations

Compilation on ESP32-C3 and existing protocol, state, crypto and
configuration checks must pass. Hardware verification must cover green
indication and one event for each of fingerprint, PIN, NFC and Lock,
including repeated operations, reboot and idle sessions. Those tests
remain required for this new event-enabled implementation.

The native wire format uses a sixteen-bit tag prefix and reuses
the key/nonce pair across request and reply. This weakens the
cryptographic guarantees of AES-GCM. Counter checks and fresh
sessions are partial protections. This beta is a compatibility
implementation; it has not established strong authorization against
an active attacker. Review these risks before controlling a real door.

Keys and private capture files are excluded from firmware commits.
