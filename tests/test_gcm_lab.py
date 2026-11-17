"""Real-crypto tests for the offline investigation tool, not the ESP32 backend."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / "tools/keypad_gcm_lab.py"
spec = importlib.util.spec_from_file_location("gcm_lab", MODULE)
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class GcmLabTest(unittest.TestCase):
    def test_known_answer_and_mutations(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            lab.selftest()
        self.assertIn("PASS", output.getvalue())

    def test_discriminates_synthetic_nonce_schedules_without_printing_secrets(self):
        _, _, _, AESGCM = lab.crypto()
        key, nonce = bytes(range(16)), bytes(range(12))
        base = int.from_bytes(nonce, "big")
        for stride, offset in ((1, 0), (1, 1), (2, 1)):
            frames = []
            for exchange in range(4):
                for direction in ("request", "reply"):
                    n = base + exchange * stride + (offset if direction == "reply" else 0)
                    payload = b"private test payload" + bytes([exchange, direction == "reply"])
                    encrypted = AESGCM(key).encrypt(n.to_bytes(12, "big"), payload, None)
                    wire = bytes([0x57 if direction == "request" else 1, 0xC6])
                    wire += encrypted[-16:-14] + encrypted[:-16]
                    frames.append({"direction": direction, "wire": wire.hex()})
            trace = {"handshake": (bytes.fromhex("01000100") + nonce + bytes(4)).hex(),
                     "frames": frames}
            with tempfile.TemporaryDirectory() as directory:
                key_path, trace_path = Path(directory) / "key", Path(directory) / "trace"
                key_path.write_text(key.hex())
                trace_path.write_text(json.dumps(trace))
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    lab.analyze(trace_path, key_path)
                report = output.getvalue()
            self.assertIn("stride=%d reply_offset=%d: 8/8" % (stride, offset), report)
            self.assertEqual(report.count("8/8"), 1)
            self.assertNotIn(key.hex(), report)
            self.assertNotIn("private test payload", report)
            self.assertNotIn(frames[0]["wire"], report)


if __name__ == "__main__":
    unittest.main()
