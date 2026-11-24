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

On 2026-11-24 the user confirmed reception in Home Assistant of
fingerprint indices 1 and 2, NFC index 1, PIN index 1 and Lock.
The supplied 22:06–22:07 log contains one completed action for each
of these five attempts, with GCM session announcements. The same log
confirms successful provisioning after the keypad itself announced
mode 00 (CTR). The user confirmed HA events; the message did not
explicitly report the LED result for each of the five attempts.
Earlier fingerprint trials with the native replies had a green LED.
The user subsequently confirmed that operation between keypad and bridge
still worked after a bridge restart, using the saved association.
Individual post-restart methods and event counts were not enumerated.

The agreed security acceptance target is parity with the native
keypad-to-lock association and action protocol. Evaluation must distinguish
native protocol limitations from additional weaknesses introduced by this
implementation. Compatibility and restart results do not alone prove parity.

The host test `tests/test_gcm_request_flow.py` compiles the actual native
request-handler branch with deterministic crypto and BLE doubles. It verifies
duplicate retransmission without advancing the counter, rejection of stale
requests and a second action, multi-poll progression, credential indices,
locked/unlocked replies, failed sends, counter overflow and the poll limit.
It tests handler state transitions, not the strength of the wire protocol.
The separate real-crypto tests verify known-answer vectors and mutations.

Remaining evidence gaps include active-adversary behavior on hardware,
power-loss and concurrency cases, native pairing confidentiality and
authentication, and the native device's own replay/rate-limit policies.
Native capture decryption establishes the accepted normal message schedule;
it does not establish the native device's behavior under malicious traffic.

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
