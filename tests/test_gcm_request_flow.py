"""Compile the actual GCM request handler with host-side BLE/crypto doubles.

Tests exercise protocol state and output selection. Real AES-GCM primitives
are covered separately by test_gcm_lab and the on-device self-tests.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "components/switchbot_keypad_bridge/switchbot_keypad_bridge.cpp"


class GcmRequestFlowTest(unittest.TestCase):
    def test_native_request_state_and_rejection(self):
        compiler = shutil.which("c++")
        if not compiler:
            self.skipTest("C++ compiler unavailable")
        source = SOURCE.read_text()
        start = source.index("  if (this->keypad_gcm_enabled_) {")
        end = source.index("  const uint8_t prefix[2]", source.index("\n    return;\n  }", start))
        block = source[start:end]
        harness = r"""
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "components/switchbot_keypad_bridge/lock_protocol.h"
#include "components/switchbot_keypad_bridge/keypad_state.h"
using namespace esphome::switchbot_keypad_bridge;
#define ESP_LOGD(...)
#define ESP_LOGW(...)
constexpr const char *TAG = "";
struct LockSession {
  static constexpr size_t MAX_PAYLOAD = 64;
  static constexpr size_t HEADER_LEN = 4;
};
void mbedtls_platform_zeroize(void *data, size_t size) { std::memset(data, 0, size); }
bool advance_gcm_probe_nonce(std::array<uint8_t, 12> &nonce) {
  for (int i = 11; i >= 0; --i) if (++nonce[i]) return true;
  return false;
}
// Deterministic doubles bind the prefix to the nonce and simulate rejection.
bool aes_gcm_decrypt_verify_prefix(const uint8_t *, const uint8_t *nonce,
    const uint8_t *input, uint8_t *output, size_t length, const uint8_t (&tag)[2]) {
  if (tag[0] != nonce[11] || tag[1] != 0xA5) return false;
  std::memcpy(output, input, length);
  return true;
}
bool aes_gcm_encrypt_raw_key(const uint8_t *, const uint8_t *nonce,
    const uint8_t *input, uint8_t *output, size_t length, uint8_t *tag) {
  std::memcpy(output, input, length);
  tag[0] = nonce[11]; tag[1] = 0xA5;
  return true;
}
struct Transport {
  bool succeed = true;
  std::vector<std::string> sent;
  bool notify(const uint8_t *data, size_t size, uint16_t) {
    if (!succeed) return false;
    sent.emplace_back(reinterpret_cast<const char *>(data), size);
    return true;
  }
};
enum class KeypadGcmProbeStage { FIRST_FRAME, WAIT_POLL, AFTER_POLL_REPLY, FINISHED };
struct Bridge {
  bool keypad_gcm_enabled_ = true;
  std::array<uint8_t, 16> shared_key_{};
  std::array<uint8_t, 12> keypad_gcm_next_nonce_{};
  std::string keypad_gcm_last_request_, keypad_gcm_last_response_;
  uint8_t keypad_gcm_poll_count_ = 0;
  DecodedCommand keypad_gcm_command_{};
  KeypadState keypad_state_{};
  KeypadGcmProbeStage keypad_gcm_probe_stage_ = KeypadGcmProbeStage::FIRST_FRAME;
  Transport transport;
  Transport *tx_characteristic_ = &transport;
  bool rejected = false;
  void reject_keypad_gcm_exchange_() {
    rejected = true;
    keypad_gcm_command_ = {};
    keypad_gcm_probe_stage_ = KeypadGcmProbeStage::FINISHED;
  }
  void process(const std::string &frame) {
    if (keypad_gcm_probe_stage_ == KeypadGcmProbeStage::FINISHED) return;
    const auto stage = keypad_gcm_probe_stage_;
    const auto *wire = reinterpret_cast<const uint8_t *>(frame.data());
    const uint16_t connection = 1;
HANDLER
  }
};
std::string packet(uint8_t counter, std::initializer_list<uint8_t> body) {
  std::string out;
  for (uint8_t v : {uint8_t(0x57), uint8_t(0x88), counter, uint8_t(0xA5)}) out += char(v);
  for (auto v : body) out += char(v);
  return out;
}
int main() {
  const auto unlock = packet(0, {0x0F,0x4E,1,3,0x0C,0x80,0x0B,0});
  Bridge b;
  b.process(unlock);
  assert(!b.rejected && b.keypad_gcm_next_nonce_[11] == 1);
  assert(b.keypad_gcm_command_.credential_index == 1);
  assert(b.keypad_gcm_command_.method == UnlockMethod::FINGERPRINT);
  assert(b.transport.sent.back().size() == 9);
  for (uint8_t method : {uint8_t(0x04), uint8_t(0x08)}) {
    Bridge credential;
    credential.process(packet(0, {0x0F,0x4E,1,3,method,0x80,0x0B,0}));
    assert(!credential.rejected && credential.keypad_gcm_command_.credential_index == 1);
    assert(uint8_t(credential.keypad_gcm_command_.method) == method);
  }
  auto reply = b.transport.sent.back();
  b.process(unlock);
  assert(b.transport.sent.back() == reply && b.keypad_gcm_next_nonce_[11] == 1);
  for (uint8_t i = 1; i <= 3; ++i) b.process(packet(i, {0x0F,0x4F,0x81,1}));
  assert(!b.rejected && b.keypad_gcm_poll_count_ == 3);
  assert(uint8_t(b.transport.sent.back()[4]) == 0x94);
  auto poll = packet(3, {0x0F,0x4F,0x81,1});
  b.process(poll);
  assert(!b.rejected && b.keypad_gcm_poll_count_ == 3);
  b.process(unlock);
  assert(b.rejected && b.keypad_gcm_command_.type == CommandType::UNKNOWN);

  Bridge bad;
  auto altered = unlock; altered[3] ^= 1;
  bad.process(altered);
  assert(bad.rejected && bad.transport.sent.empty());
  Bridge old_session;
  old_session.keypad_gcm_next_nonce_[11] = 40;
  old_session.process(unlock);
  assert(old_session.rejected && old_session.transport.sent.empty());

  Bridge locked;
  locked.process(packet(0, {0x0F,0x4E,1,3,0,0,0,0}));
  assert(uint8_t(locked.transport.sent.back()[4]) == 0x86);

  Bridge overflow;
  overflow.keypad_gcm_next_nonce_.fill(0xFF);
  overflow.process(packet(0xFF, {0x0F,0x4E,1,3,0x0C,0x80,0x0B,0}));
  assert(overflow.rejected && overflow.transport.sent.empty());
  locked.process(packet(1, {0x0F,0x4F,0x81,1}));
  assert(uint8_t(locked.transport.sent.back()[4]) == 0x86);

  Bridge second_action;
  second_action.process(unlock);
  second_action.process(packet(1, {0x0F,0x4E,1,3,0x0C,0x80,0x0C,0}));
  assert(second_action.rejected);

  Bridge failed_send;
  failed_send.transport.succeed = false;
  failed_send.process(unlock);
  assert(failed_send.rejected);

  Bridge limit;
  limit.process(unlock);
  for (uint8_t i = 1; i <= 16; ++i) limit.process(packet(i, {0x0F,0x4F,0x81,1}));
  assert(!limit.rejected);
  limit.process(packet(17, {0x0F,0x4F,0x81,1}));
  assert(limit.rejected);
}
"""
        with tempfile.TemporaryDirectory() as directory:
            cpp = Path(directory) / "flow.cpp"
            binary = Path(directory) / "flow"
            cpp.write_text(harness.replace("HANDLER", block))
            subprocess.run(
                [compiler, "-std=c++17", "-I", str(ROOT), str(cpp),
                 str(ROOT / "components/switchbot_keypad_bridge/lock_protocol.cpp"),
                 "-o", str(binary)], check=True, capture_output=True, text=True,
            )
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
