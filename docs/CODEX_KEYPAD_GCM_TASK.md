# Codex implementation task: Experimental keypad → bridge AES-GCM

## Goal

Implement **opt-in experimental AES-GCM** for Bluetooth communications **from an updated SwitchBot keypad to this ESPHome bridge**, which impersonates a SwitchBot lock (BLE peripheral/server). Keep existing AES-CTR behavior unchanged by default. This task is a protocol-compatibility implementation and investigation, **not** a claim of full security remediation until validated.

**Work on branch** `feat/keypad-gcm-experimental`, opening a PR **against this fork's `main`**. Do not merge automatically, do not rotate saved credentials, and do not modify upstream.

## Starting point / precise code map

- `components/switchbot_keypad_bridge/lock_session.h` and `.cpp`: keypad-facing session. Currently uses a 16-byte CTR IV, responds to a session request with `01 00 00 00 || IV[16]` (20 bytes), and uses received header bytes 2–3 as an echo of the first two IV bytes to select active/pending/retired contexts. This is **not correct for GCM**, where those two header bytes instead contain a truncated tag.
- `components/switchbot_keypad_bridge/switchbot_keypad_bridge.cpp`: BLE GATT server and `on_rx_frame_`; `import_aes_key_` imports PSA AES key with `PSA_ALG_CTR` (CTR-only key handle).
- `components/switchbot_keypad_bridge/aes_ctr.h` and `.cpp`: CTR primitive plus GCM raw-key encrypt/decrypt helpers. The existing `aes_gcm_decrypt_raw_key` **does not authenticate the received message/tag**.
- `components/switchbot_keypad_bridge/physical_lock.cpp`: separate BLE **client** for physical SwitchBot locks. It supports GCM as a client; its flow is useful for crypto primitives but **does not implement the keypad-facing GCM server state machine**.
- `components/switchbot_keypad_bridge/keypad_pairer.cpp`: separate keypad provisioning/association. Keep unchanged unless captures show it must be updated.
- `components/switchbot_keypad_bridge/__init__.py`: ESPHome configuration schema and code generation.
- `tests/lock_session_test.cpp`, `tests/run_lock_session_tests.sh`: existing standalone regression suite.

## Protocol references (client implementations; verify direction-specific behavior)

1. [pySwitchbot encrypted device](https://github.com/sblibs/pySwitchbot/blob/main/switchbot/devices/device.py), [unit tests](https://github.com/sblibs/pySwitchbot/blob/main/tests/test_encrypted_device.py):
   - Session request: `57 00 00 00 0F 21 03 <key_id>`.
   - Negotiated cipher mode byte: CTR = `0x00`; GCM = `0x01`.
   - Client-side GCM handshake parser reads `01 00 01 00 || IV[12] || trailing[4]`; GCM nonce is 12 bytes and CTR IV is 16 bytes. **Meaning of final four bytes is not established; investigate and document.**
   - The encrypted GCM command's header bytes 2–3 carry the **first two bytes of the computed GCM authentication tag**, not an IV echo.
   - pySwitchbot increments the 12-byte GCM nonce in big-endian order after the round trip. **This does not establish exact receive/reply counter semantics in server mode.**
   - pySwitchbot decrypts certain device responses without authenticating their incomplete 2-byte tag. **Do not emulate this for incoming authorization commands.**
2. [OpenSB crypto](https://github.com/MyrikLD/opensb/blob/main/packages/opensb-core/src/opensb/ble/crypto.py) and [session](https://github.com/MyrikLD/opensb/blob/main/packages/opensb-core/src/opensb/ble/session.py) are additional client-side references.
3. [Upstream Security limits](https://github.com/pierluigizagaria/switchbot-keypad-bridge#security-limits) documents the current CTR malleability and replay limitation. Do not silently change its stated threat model.

## Phase A — evidence, design, and observability (do this first)

- [ ] Trace all messages and paths in the current keypad-facing BLE server; keep separate keypad→bridge, bridge→keypad, keypad pairing, and bridge→physical-lock roles.
- [ ] Write `docs/keypad-gcm-protocol.md` with known fields, observed data, explicit unknowns, and a state transition diagram.
- [ ] Investigate GCM handshake **trailing four bytes**, whether a keypad accepts the bridge advertising GCM, nonce use per direction, whether/how the keypad increments a nonce, and rotation during Vision fast unlock.
- [ ] If these cannot be derived from trustworthy source/tests, make the experimental implementation explicitly conditional on a **real updated keypad handshake capture**. Never invent protocol bytes or falsely report success.
- [ ] Add diagnostic logging (mode, handshake length, nonsecret status codes, error reason), but **never** log keys, PINs, credentials, raw plaintext, or sensitive full BLE traffic in ordinary logs.

## Phase B — opt-in GCM handshake

- [ ] Add an explicit experimental configuration flag such as `keypad_crypto_mode: gcm_experimental` to the existing ESPHome schema. Default remains `ctr`.
- [ ] Implement a well-defined GCM session response with mode byte 1 and 12-byte random nonce, plus correct (verified) trailing fields. Avoid weak RNG or nonce reuse under the same key. Adjust response size accessors as needed; do not assume 20 bytes implies CTR.
- [ ] When GCM mode is selected, **do not silently negotiate or fall back to CTR** if GCM fails.
- [ ] Do not reset existing pairing, alter shared keys, or change the provisioning workflow without evidence.

## Phase C — GCM receive/reply as a BLE server

- [ ] Add explicit CTR/GCM modes in the session state; do not reuse the CTR `seq_a/seq_b == IV[0..1]` generation selector for GCM packets.
- [ ] Ensure key handling supports the GCM primitive: the current PSA key handle is CTR-only. Reuse existing GCM raw-key code carefully or add a distinct correctly scoped GCM key.
- [ ] For incoming GCM commands, calculate the expected GCM authentication tag for the actual nonce/message and compare the received **2-byte tag prefix** in constant time **before decoding, emitting an event, ACKing acceptance, or relaying a physical-lock command**. Reject invalid frames and do not produce action side effects.
- [ ] A 2-byte tag gives only 16 bits of wire authentication data, **not** the usual 128-bit GCM tag: explicitly document the limitations and do not claim “full authenticated encryption” or vulnerability elimination.
- [ ] Determine and implement the correct nonce progression and relation between incoming command and outgoing response; ensure distinct plaintexts are not encrypted with a reused (key, nonce) pair, and old frames cannot be mistaken for current session data.
- [ ] Encrypt responses in GCM with the expected status/header/tag prefix, preserving Lock, Unlock (PIN/NFC/fingerprint/face/palm), Doorbell, and state poll paths.
- [ ] Preserve the default CTR anti-replay history and active/pending/retired IV handling unchanged. Implement any GCM replay/session generation logic based on actual protocol evidence, **not** the assumption that GCM by itself provides replay protection.
- [ ] Reconnect, reset, wrong slot, wrong frame length, unknown command/method and overlapping IV rotation must fail closed.

## Phase D — tests, compatibility and docs

- [ ] Create deterministic unit tests for handshake layout/mode/IV lengths and for AES-GCM crypto using known test vectors.
- [ ] Test correct tag prefix, single-bit ciphertext mutation, tag mutation, replay, wrong key/slot, stale session, reset/reconnect, multiple successive actions, rotation, partial IV handoff and rapid Vision polling.
- [ ] Assert failed validation never publishes an event or triggers a physical relay.
- [ ] Keep `sh tests/run_lock_session_tests.sh` passing for CTR, without weakening existing replay tests.
- [ ] Run applicable existing tests and ESPHome compilation for at least one board (e.g. `tests/compile.wt32-eth01.yaml`); list commands and actual results. **Not run** is not **passed**.
- [ ] Supply a manual updated-device test matrix: keypad model, precise firmware revision, configured mode, initial association state, handshake outcome, credential event, replays, fast re-entry, reconnect, optional physical lock relay. Never publish actual user secrets or identifying captures.
- [ ] Update README configuration and **Security limits** to distinguish implemented validation, incomplete 16-bit tag, remaining assumptions, experimental compatibility and no silent downgrade.

## Acceptance criteria

- [ ] Opt-in GCM compiles, rejects malformed or tag-mismatched incoming messages, and never silently downgrades.
- [ ] Incoming action must be rejected before event/relay unless cryptographic and state validations pass.
- [ ] GCM handshake behavior is supported by references and/or real hardware captures; unresolved unknowns are documented as blockers rather than guessed.
- [ ] CTR remains exactly the current default behavior, with regression tests still green.
- [ ] Tests cover both positive and negative flows; include actual test/build results in PR.
- [ ] Documentation is accurate about the **16-bit truncated tag** and does not declare the implementation secure or compatible on firmware/models that have not been tested.
- [ ] Codex opens a PR into `robertoamd90/switchbot-keypad-bridge:main` referencing this specification, with technical notes and test results; do not merge automatically.

## Suggested execution order

First commit: protocol note + tests for GCM frame layout (no new production behavior). Second: feature flag and handshake. Third: receiving/verifying GCM + responses. Fourth: regression tests, documentation, manual test checklist. If the handshake or direction/nonce rules prove underspecified, **stop and write down exactly which non-secret trace is needed** rather than adding unverified behavior.

---

This task specification is maintained in the fork because GitHub Issues were disabled when the task was created. Enable Issues in repository Settings if you want to migrate this text into a native issue later.
