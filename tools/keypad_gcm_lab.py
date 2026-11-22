#!/usr/bin/env python3
"""Offline GCM evidence checks. Never prints keys, frames or plaintext.

This is an investigation tool, not an implementation of keypad server rules.
"""
import argparse
from collections import Counter
import glob
import hmac
import importlib.util
import json
from pathlib import Path
import shutil
import sys


def crypto():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise ValueError("cryptography missing; install tools/requirements-gcm.txt") from None
    return Cipher, algorithms, modes, AESGCM


def tag_matches(key, nonce, wire):
    """Check the two-byte prefix with empty AAD, without releasing plaintext.

    Decryption before verification is confined to this offline function. Re-encrypt
    the candidate plaintext to calculate the full expected tag; never decode it.
    Empty AAD is a reference-client hypothesis, not a proven keypad-server rule.
    """
    Cipher, algorithms, modes, AESGCM = crypto()
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, bytes(16))).decryptor()
    candidate = decryptor.update(wire[4:])
    expected = AESGCM(key).encrypt(nonce, candidate, None)
    return hmac.compare_digest(expected[-16:-14], wire[2:4])


def selftest():
    _, _, _, AESGCM = crypto()
    # NIST SP 800-38D, zero-key/zero-IV single-block GCM example.
    key, nonce, plaintext = bytes(16), bytes(12), bytes(16)
    expected = bytes.fromhex(
        "0388dace60b6a392f328c2b971b2fe78"
        "ab6e47d42cec13bdf53a67b21257bddf"
    )
    actual = AESGCM(key).encrypt(nonce, plaintext, None)
    if actual != expected:
        raise ValueError("known-answer vector failed")
    wire = bytes([0x57, 0xC6]) + actual[-16:-14] + actual[:-16]
    if not tag_matches(key, nonce, wire):
        raise ValueError("valid prefix rejected")
    for offset in range(2, len(wire)):
        for bit in range(8):
            changed = bytearray(wire)
            changed[offset] ^= 1 << bit
            if tag_matches(key, nonce, bytes(changed)):
                raise ValueError("mutation unexpectedly matched in fixed test vector")
    if tag_matches(bytes([1]) + key[1:], nonce, wire):
        raise ValueError("wrong-key test unexpectedly matched")
    if tag_matches(key, bytes(11) + b"\x01", wire):
        raise ValueError("wrong-nonce test unexpectedly matched")
    print("PASS: real AES-GCM known-answer vector, two-byte prefix, all single-bit")
    print("ciphertext/tag mutations in this vector, wrong key and wrong nonce.")
    print("This does not validate ESP32 crypto, replay protection or keypad compatibility.")


def doctor():
    print("Python:", sys.version.split()[0])
    for module in ("cryptography", "esphome", "bleak"):
        print(module + ":", "available" if importlib.util.find_spec(module) else "missing")
    for command in ("esphome", "cmake", "ninja"):
        print("PATH " + command + ":", shutil.which(command) or "not on PATH (module may still be available)")
    print("Serial ports:", ", ".join(glob.glob("/dev/cu.*")) or "none detected")
    print("BLE sniffing capability is not established by the presence of a serial port.")


def analyze(trace_path, key_path):
    # Keep key material in a separate local file, never a CLI argument/log.
    key = bytes.fromhex(Path(key_path).read_text().strip())
    if len(key) != 16:
        raise ValueError("key file must contain one 16-byte hex key")
    trace = json.loads(Path(trace_path).read_text())
    handshake = bytes.fromhex(trace["handshake"])
    if len(handshake) != 20 or handshake[:4] != bytes.fromhex("01000100"):
        raise ValueError("expected a 20-byte GCM reference handshake")
    frames = trace["frames"]
    if not frames:
        raise ValueError("trace has no frames")
    nonce_base = int.from_bytes(handshake[4:16], "big")
    records = []
    round_trip = 0
    awaiting_reply = False
    for record in frames:
        direction = record["direction"]
        wire = bytes.fromhex(record["wire"])
        if direction not in ("request", "reply") or len(wire) <= 4:
            raise ValueError("records must contain encrypted request/reply frames")
        if wire[0] != (0x57 if direction == "request" else 0x01):
            raise ValueError("unexpected frame status/magic; split the trace at errors")
        if (direction == "request") == awaiting_reply:
            raise ValueError("use alternating request/reply frames; no loss/retries in this first analysis")
        records.append((round_trip, direction, wire))
        awaiting_reply = direction == "request"
        if direction == "reply":
            round_trip += 1
    if awaiting_reply:
        raise ValueError("last request has no reply")
    trailer = handshake[16:20]
    trailer_class = "all-zero" if trailer == bytes(4) else "nonzero"
    print(f"GCM handshake parsed: four-byte trailer is {trailer_class} (meaning unknown).")
    # Candidate schedules only. Never select one automatically as firmware policy.
    for stride, reply_offset in ((1, 0), (1, 1), (2, 1)):
        matched = Counter()
        nonce_uses = Counter()
        for exchange, direction, wire in records:
            value = nonce_base + exchange * stride + (reply_offset if direction == "reply" else 0)
            if value >= 1 << 96:
                raise ValueError("candidate nonce overflow")
            if tag_matches(key, value.to_bytes(12, "big"), wire):
                matched[direction] += 1
                nonce_uses[value] += 1
        matches = sum(matched.values())
        print("candidate stride=%d reply_offset=%d: %d/%d tag-prefix matches" %
              (stride, reply_offset, matches, len(records)))
        reused = sum(count > 1 for count in nonce_uses.values())
        print(f"  requests={matched['request']}/{round_trip} replies={matched['reply']}/{round_trip}"
              f" repeated_nonces_among_matches={reused}")
    print("16-bit matches are evidence, not proof. No slot binding or replay validation performed.")
    print("Split captures at handshakes; this analyzer does not infer rotation or retransmissions.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor")
    commands.add_parser("selftest")
    analysis = commands.add_parser("analyze")
    analysis.add_argument("trace", help="private JSON capture, see docs/keypad-gcm-protocol.md")
    analysis.add_argument("--key-file", required=True, help="private hex key file")
    args = parser.parse_args()
    try:
        if args.command == "doctor":
            doctor()
        elif args.command == "selftest":
            selftest()
        else:
            analyze(args.trace, args.key_file)
    except (ValueError, KeyError, TypeError, OSError):
        # Do not echo parser/library exceptions that could contain private input.
        print("ERROR: dependency unavailable or invalid input; check the documented format.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
