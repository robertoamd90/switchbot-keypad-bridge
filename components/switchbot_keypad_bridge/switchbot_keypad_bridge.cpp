#include "switchbot_keypad_bridge.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

#include <esp_mac.h>
#include <esp_random.h>
#include <mbedtls/platform_util.h>
#include <psa/crypto.h>

#include "esphome/core/hal.h"
#include "esphome/core/log.h"
#include "ble_utils.h"
#include "aes_ctr.h"
#include "keypad_advert.h"
#include "mac_utils.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

const char *const TAG = "switchbot_keypad_bridge";

// SwitchBot's OUI. Applied to the chip's factory MAC at boot so the bridge
// advertises within SwitchBot's address range — the Keypad Vision filters
// scan results on this prefix.
constexpr uint8_t SPOOFED_OUI[3] = {0xB0, 0xE9, 0xFE};

// Manufacturer-specific advertising blob published by the genuine lock.
constexpr uint8_t ADVERTISING_MFG_DATA[] = {0x27, 0x09, 0x00, 0x10,
                                            0xA5, 0xB8, 0x00, 0x00, 0x00};

// Encrypted response payloads sent back to the keypad on lock/unlock.
constexpr uint8_t RESPONSE_LOCK[5]   = {0x90, 0x0A, 0x7F, 0x7F, 0x00};
constexpr uint8_t RESPONSE_UNLOCK[5] = {0x98, 0x08, 0x7F, 0x7F, 0x00};

// Trailing 13 bytes appended to the lock-state byte when answering a state poll.
constexpr uint8_t STATE_PAYLOAD_TAIL[13] = {0x08, 0x08, 0x41, 0x00, 0x00, 0x00, 0x00,
                                            0x80, 0xF2, 0xFB, 0x00, 0x00, 0x00};

constexpr uint8_t SHARED_SLOT_ORIGINAL = 0x88;
constexpr uint8_t SHARED_SLOT_VISION   = 0xC6;

constexpr size_t AES_KEY_SIZE = 16;
constexpr uint32_t GCM_EXCHANGE_TIMEOUT_MS = 10000;
constexpr uint32_t GCM_FAILURE_WINDOW_MS = 60000;
constexpr uint8_t GCM_FAILURE_LIMIT = 3;

// Battery advert scan: one short active window per interval.
constexpr uint32_t BATTERY_SCAN_DURATION_MS = 5000;
constexpr uint32_t BATTERY_SCAN_RETRY_MS    = 30000;

bool is_shared_slot(uint8_t slot) {
  return slot == SHARED_SLOT_ORIGINAL || slot == SHARED_SLOT_VISION;
}

bool advance_gcm_probe_nonce(std::array<uint8_t, 12> &nonce) {
  for (auto byte = nonce.rbegin(); byte != nonce.rend(); ++byte) {
    if (++*byte != 0)
      return true;
  }
  return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// NimBLE callback bridges
// ---------------------------------------------------------------------------

class SwitchbotKeypadBridge::ServerCallbacks : public NimBLEServerCallbacks {
 public:
  explicit ServerCallbacks(SwitchbotKeypadBridge *parent) : parent_(parent) {}

  void onConnect(NimBLEServer *server, NimBLEConnInfo &info) override {
    this->parent_->enqueue_ble_event_({QueuedEvent::CONNECT, info.getConnHandle(), {}});
  }

  void onDisconnect(NimBLEServer *server, NimBLEConnInfo &info, int reason) override {
    this->parent_->enqueue_ble_event_({QueuedEvent::DISCONNECT, info.getConnHandle(), {}});
  }

 private:
  SwitchbotKeypadBridge *parent_;
};

class SwitchbotKeypadBridge::RxCharCallbacks : public NimBLECharacteristicCallbacks {
 public:
  explicit RxCharCallbacks(SwitchbotKeypadBridge *parent) : parent_(parent) {}

  void onWrite(NimBLECharacteristic *characteristic, NimBLEConnInfo &info) override {
    const std::string value = characteristic->getValue();
    if (value.empty())
      return;
    this->parent_->enqueue_ble_event_({QueuedEvent::RX, info.getConnHandle(), value});
  }

 private:
  SwitchbotKeypadBridge *parent_;
};

class SwitchbotKeypadBridge::BatteryScanCallbacks : public NimBLEScanCallbacks {
 public:
  explicit BatteryScanCallbacks(SwitchbotKeypadBridge *parent) : parent_(parent) {}

  void onResult(const NimBLEAdvertisedDevice *adv) override {
    this->parent_->handle_battery_advert_(adv);
  }

 private:
  SwitchbotKeypadBridge *parent_;
};

// ---------------------------------------------------------------------------
// Thread-safe event queueing
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::enqueue_ble_event_(QueuedEvent event) {
  std::lock_guard<std::mutex> lk(this->rx_mutex_);
  this->rx_queue_.push_back(std::move(event));
}

// ---------------------------------------------------------------------------
// Component lifecycle
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::setup() {
  // Load — or, on first boot, generate — the 16-byte AES-128 session key.
  // reset_pairing() rotates it; it is never part of the YAML config.
  this->shared_key_pref_ =
      global_preferences->make_preference<std::array<uint8_t, 16>>(0x534B4559UL /* 'SKEY' */);
  if (!this->shared_key_pref_.load(&this->shared_key_)) {
    this->create_shared_key_();
    ESP_LOGI(TAG, "Generated a fresh shared key");
  }

  // Restore the linked keypad name (if any) and publish it to the sensor.
  this->keypad_name_pref_ = global_preferences->make_preference<char[KEYPAD_NAME_MAX]>(
      0x534B5042UL /* 'SKPB' */);
  char stored_name[KEYPAD_NAME_MAX] = {};
  bool have_keypad = false;
  if (this->keypad_name_pref_.load(&stored_name) && stored_name[0] != '\0') {
    stored_name[KEYPAD_NAME_MAX - 1] = '\0';
    have_keypad = true;
    if (this->keypad_text_sensor_ != nullptr) {
      this->keypad_text_sensor_->publish_state(stored_name);
    }
    ESP_LOGI(TAG, "Linked keypad: '%s'", stored_name);
  } else {
    if (this->keypad_text_sensor_ != nullptr) {
      this->keypad_text_sensor_->publish_state("Unlinked");
    }
  }
  this->keypad_paired_ = have_keypad;
  this->pairing_ui_.set_keypad_paired(have_keypad);

  // Restore the keypad MAC + family used by the battery advert scan. Missing
  // for keypads linked before this field existed — the scan learns it then.
  this->keypad_info_pref_ =
      global_preferences->make_preference<KeypadInfo>(0x534B4D43UL /* 'SKMC' */);
  if (!this->keypad_info_pref_.load(&this->keypad_info_)) {
    this->keypad_info_ = KeypadInfo{};
  }
  if (this->keypad_info_.valid != 0) {
    this->pairing_ui_.set_keypad_family(
        static_cast<KeypadFamily>(this->keypad_info_.family));
  }
  this->linked_lock_pref_ =
      global_preferences->make_preference<LinkedLockInfo>(0x534C4F43UL /* 'SLOC' */);
  if (!this->linked_lock_pref_.load(&this->linked_lock_info_)) {
    this->linked_lock_info_ = LinkedLockInfo{};
  } else {
    bool had_private_key_material = false;
    for (uint8_t b : this->linked_lock_info_.reserved) {
      if (b != 0) {
        had_private_key_material = true;
        break;
      }
    }
    if (this->linked_lock_info_.valid != 0 &&
        (had_private_key_material || !is_shared_slot(this->linked_lock_info_.slot_id))) {
      ESP_LOGW(TAG, "Ignoring legacy linked-lock record that was not shared-key based");
      this->linked_lock_info_ = LinkedLockInfo{};
      this->save_and_sync_(this->linked_lock_pref_, &this->linked_lock_info_);
    }
  }
  this->lock_linked_ = this->linked_lock_info_.valid != 0;
  this->pairing_ui_.set_lock_linked(this->lock_linked_);
  this->publish_linked_lock_();
  this->battery_scan_callbacks_ = new BatteryScanCallbacks(this);
  this->next_battery_scan_at_ = millis() + BATTERY_SCAN_RETRY_MS;
  if (!this->lock_linked_) {
    this->clear_lock_battery_();
  }

  if (!this->prepare_keys_() || !this->prepare_ble_()) {
    this->mark_failed();
    return;
  }
  ESP_LOGI(TAG, "Ready. Advertising on %s",
           NimBLEDevice::getAddress().toString().c_str());
  if (this->keypad_gcm_experimental_) {
    ESP_LOGI(TAG, "Keypad crypto mode: gcm_experimental (standalone Touch test)");
  }

  this->pairing_ui_.set_shared_key(this->shared_key_);
  this->pairing_ui_.set_on_paired_callback(
      [this](const std::string &name, const std::string &mac,
             KeypadFamily family) {
        // Runs from PairingUi::poll_jobs() in loop(); keep the apply path
        // centralized below so publishing and NVS writes stay in one place.
        this->pending_keypad_name_ = name;
        this->pending_keypad_mac_ = mac;
        this->pending_keypad_family_ = family;
        this->pending_pair_apply_.store(true, std::memory_order_release);
      });
  this->pairing_ui_.set_on_lock_linked_callback(
      [this](const std::string &name, const std::string &mac,
             PhysicalLockModel model, uint8_t slot_id) {
        this->pending_lock_name_ = name;
        this->pending_lock_mac_ = mac;
        this->pending_lock_model_ = model;
        this->pending_lock_slot_id_ = slot_id;
        this->pending_lock_apply_.store(true, std::memory_order_release);
      });
  // Setup mode: with no keypad linked yet, open the wizard right away
  // so the very first link needs no button press.
  if (!have_keypad || this->gcm_diagnostics_) {
    if (this->pairing_ui_.start()) {
      ESP_LOGI(TAG, "%s", have_keypad ? "Starting GCM diagnostics wizard"
                                      : "No keypad linked — starting setup mode");
    } else {
      ESP_LOGW(TAG, "Setup UI failed to start; check port 80 is free");
    }
  }
}

void SwitchbotKeypadBridge::loop() {
  this->update_keypad_gcm_probe_();
  // Observe finished wizard jobs from the main loop — this queues the pending
  // applies below even when the browser stopped polling mid-job.
  if (this->pairing_ui_.is_running()) {
    this->pairing_ui_.poll_jobs();
  }

  this->apply_pending_pairing_();
  this->apply_pending_lock_link_();
  this->apply_pending_lock_relay_();
  this->update_rearm_timer_();

  // Idle-close the wizard only once a keypad is linked: with nothing linked
  // the wizard is the device's whole purpose ("setup mode") and must stay
  // reachable — closing it would strand the first-boot flow behind the Reset
  // button, which needlessly rotates the shared key.
  if (this->keypad_paired_ && this->pairing_ui_.stop_if_idle(millis())) {
    ESP_LOGI(TAG, "Setup UI stopped after 5 minutes of inactivity");
  }

  // Drain the RX queue. Swapping the vector out keeps the critical section
  // free of allocation and copying, so the NimBLE task never waits on it.
  std::vector<QueuedEvent> pending;
  {
    std::lock_guard<std::mutex> lk(this->rx_mutex_);
    pending.swap(this->rx_queue_);
  }

  for (const auto &ev : pending) {
    if (ev.type == QueuedEvent::CONNECT) {
      ESP_LOGI(TAG, "Keypad connected");
      if (this->keypad_gcm_experimental_) {
        if (this->keypad_gcm_connection_ == BLE_HS_CONN_HANDLE_NONE) {
          this->keypad_gcm_connection_ = ev.connection;
          this->keypad_gcm_connection_started_ = millis();
          this->keypad_gcm_probe_slot_ = 0;
          this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::FIRST_FRAME;
          this->keypad_gcm_command_ = {};
          this->keypad_gcm_reference_active_ = this->gcm_diagnostics_ &&
              this->pairing_ui_.take_keypad_reference_probe(this->keypad_gcm_reference_state_);
        }
      } else {
        this->keypad_gcm_probe_slot_ = 0;
      }
      this->session_.reset_transport();
    } else if (ev.type == QueuedEvent::DISCONNECT) {
      ESP_LOGI(TAG, "Keypad disconnected, restarting advertising");
      if (this->keypad_gcm_experimental_) {
        if (ev.connection == this->keypad_gcm_connection_) {
          const auto command = this->keypad_gcm_command_;
          const auto stage = this->keypad_gcm_probe_stage_;
          if (stage == KeypadGcmProbeStage::HOLD_POLL_REPLY) {
            ESP_LOGI(TAG, "Poll hold: disconnected at +%u ms before reply (control=%s)",
                     unsigned(millis() - this->poll_hold_started_), this->withhold_this_poll_reply_ ? "yes" : "no");
          }
          const bool reference_test = this->keypad_gcm_reference_active_;
          const bool complete = stage == KeypadGcmProbeStage::AFTER_POLL_REPLY &&
              millis() - this->keypad_gcm_connection_started_ < GCM_EXCHANGE_TIMEOUT_MS;
          this->keypad_gcm_connection_ = BLE_HS_CONN_HANDLE_NONE;
          this->keypad_gcm_probe_slot_ = 0;
          this->keypad_gcm_command_ = {};
          this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::FINISHED;
          this->keypad_gcm_reference_active_ = false;
          if (stage == KeypadGcmProbeStage::WAIT_POLL) {
            ESP_LOGI(TAG, "GCM experimental action incomplete: disconnected before a valid state poll");
          }
          if (reference_test) {
            ESP_LOGI(TAG, "Keypad GCM reference test ended: poll reply %s; events suspended for this test",
                     complete ? "sent" : "not completed");
          }
          if (this->gcm_lock_slot_test_ && complete) {
            ESP_LOGI(TAG, "Keypad GCM slot test: poll observed; action events suspended");
          }
          if (this->gcm_empty_ack_test_) {
            ESP_LOGI(TAG, "Keypad GCM empty ACK test ended: poll reply %s; actions suspended",
                     complete ? "sent" : "not completed");
          }
          if (this->gcm_native_reply_test_) {
            ESP_LOGI(TAG, "GCM native reply test ended: poll reply %s; actions suspended",
                     complete ? "sent" : "not completed");
          }
          if (!this->gcm_native_reply_test_ && !this->gcm_empty_ack_test_ && !this->gcm_lock_slot_test_ && !reference_test && complete &&
              this->keypad_paired_ && !this->lock_linked_) {
            if (command.type == CommandType::LOCK) {
              this->keypad_state_.rearm();
              ESP_LOGI(TAG, "GCM experimental lock");
              this->publish_lock_();
            } else if (command.type == CommandType::UNLOCK) {
              this->keypad_state_.unlock(millis());
              ESP_LOGI(TAG, "GCM experimental unlock: method=%s index=%d",
                       unlock_method_name(command.method), command.credential_index);
              this->publish_unlock_(command.method, command.credential_index);
            }
          }
        }
      } else {
        this->keypad_gcm_probe_slot_ = 0;
      }
      if (this->keypad_gcm_probe_active_ &&
          this->keypad_gcm_probe_stage_ == KeypadGcmProbeStage::AFTER_POLL_REPLY) {
        this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::FINISHED;
        ESP_LOGI(TAG, "Keypad GCM probe: disconnected after poll reply; no third frame observed");
      }
      this->session_.reset_transport();
      NimBLEDevice::startAdvertising();
    } else if (ev.type == QueuedEvent::RX) {
      this->on_rx_frame_(ev.frame, ev.connection);
    }
  }

  if (this->keypad_gcm_probe_stage_ == KeypadGcmProbeStage::HOLD_POLL_REPLY &&
      !this->withhold_this_poll_reply_ &&
      millis() - this->poll_hold_started_ >= 2000) {
    this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::FINISHED;
    if (millis() - this->keypad_gcm_connection_started_ < GCM_EXCHANGE_TIMEOUT_MS &&
        this->tx_characteristic_->notify(this->held_poll_reply_.data(), this->held_poll_reply_.size(),
                                        this->keypad_gcm_connection_)) {
      this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::AFTER_POLL_REPLY;
      ESP_LOGI(TAG, "Poll hold: reply submitted at +%u ms", unsigned(millis() - this->poll_hold_started_));
    } else {
      ESP_LOGW(TAG, "Poll hold: reply not submitted at +%u ms", unsigned(millis() - this->poll_hold_started_));
    }
  }

  if (this->keypad_battery_level_sensor_ != nullptr ||
      this->lock_battery_level_sensor_ != nullptr) {
    this->apply_pending_keypad_battery_();
    this->apply_pending_lock_battery_();
    this->maybe_finish_battery_scan_();
    this->maybe_start_battery_scan_();
  }
}

void SwitchbotKeypadBridge::apply_pending_pairing_() {
  if (this->pending_pair_apply_.exchange(false, std::memory_order_acquire)) {
    const std::string &name = this->pending_keypad_name_;

    // Persist the name so it survives a reboot and can be re-published.
    char buf[KEYPAD_NAME_MAX] = {};
    name.copy(buf, sizeof(buf) - 1);
    const bool saved = this->keypad_name_pref_.save(&buf);

    // Persist the keypad's MAC + family for the battery advert scan.
    KeypadInfo info{};
    if (parse_mac_pretty(this->pending_keypad_mac_, info.mac)) {
      info.family = static_cast<uint8_t>(this->pending_keypad_family_);
      info.valid = 1;
    }
    this->keypad_info_ = info;
    this->keypad_state_.rearm();
    this->save_and_sync_(this->keypad_info_pref_, &this->keypad_info_);

    this->keypad_paired_ = true;
    this->pairing_ui_.set_keypad_paired(true);
    this->pairing_ui_.set_keypad_family(this->pending_keypad_family_);
    this->last_keypad_battery_ = -1;
    // Pick the new keypad's battery up shortly, not a full interval away.
    this->next_battery_scan_at_ = millis() + 10000;

    this->publish_text_or_unlinked_(this->keypad_text_sensor_, name.c_str());
    ESP_LOGI(TAG, "Linked keypad: '%s' (nvs save %s)", name.c_str(),
             saved ? "ok" : "FAILED");

    ESP_LOGI(TAG, "Setup UI remains open for lock linking until it is idle");
  }
}

void SwitchbotKeypadBridge::apply_pending_lock_link_() {
  if (this->pending_lock_apply_.exchange(false, std::memory_order_acquire)) {
    LinkedLockInfo info{};
    if (parse_mac_pretty(this->pending_lock_mac_, info.mac)) {
      info.valid = 1;
      info.model = static_cast<uint8_t>(this->pending_lock_model_);
      info.slot_id = this->pending_lock_slot_id_;
      this->pending_lock_name_.copy(info.name, sizeof(info.name) - 1);
    }
    this->linked_lock_info_ = info;
    this->lock_linked_ = info.valid != 0;
    this->pairing_ui_.set_lock_linked(this->lock_linked_);
    this->save_and_sync_(this->linked_lock_pref_, &this->linked_lock_info_);
    this->publish_linked_lock_();
    this->clear_lock_battery_();
    this->next_battery_scan_at_ = millis() + 5000;
    if (this->lock_linked_) {
      ESP_LOGI(TAG, "Linked physical lock: '%s' (%s, shared_slot=0x%02X)",
               this->linked_lock_info_.name,
               physical_lock_model_str(static_cast<PhysicalLockModel>(this->linked_lock_info_.model)),
               this->linked_lock_info_.slot_id);
    } else {
      ESP_LOGW(TAG, "Ignoring linked lock apply with invalid MAC");
    }
  }
}

void SwitchbotKeypadBridge::apply_pending_lock_relay_() {
  if (this->pending_relay_apply_.exchange(false, std::memory_order_acquire)) {
    if (!this->relay_ok_) {
      ESP_LOGW(TAG, "Physical lock relay finished without a lock reply");
      return;
    }
    switch (this->relay_command_.type) {
      case CommandType::LOCK:
        ESP_LOGI(TAG, "Physical lock relay confirmed Lock");
        return;
      case CommandType::UNLOCK:
        ESP_LOGI(TAG, "Physical lock relay confirmed Unlock: method=%s index=%d",
                 unlock_method_name(this->relay_command_.method),
                 this->relay_command_.credential_index);
        return;
      default:
        ESP_LOGD(TAG, "Physical lock replied to forwarded command");
        return;
    }
  }
}

void SwitchbotKeypadBridge::reset_pairing() {
  ESP_LOGI(TAG, "Resetting links — rotating the shared key and re-opening the setup wizard");

  // Rotate the key and swap it into the live crypto slot: the previously
  // linked keypad can no longer command the bridge, with no reboot needed.
  this->create_shared_key_();
  if (!this->import_aes_key_()) {
    ESP_LOGE(TAG, "Key rotation failed — reset aborted");
    return;
  }

  // Stop an in-flight battery scan window: the wizard's own blocking scans
  // share the NimBLE scan singleton and must not race it.
  this->stop_battery_scan_();

  // Forget the linked keypad name and its battery-scan identity.
  char empty[KEYPAD_NAME_MAX] = {};
  this->keypad_name_pref_.save(&empty);
  this->keypad_info_ = KeypadInfo{};
  this->keypad_info_pref_.save(&this->keypad_info_);
  this->linked_lock_info_ = LinkedLockInfo{};
  this->linked_lock_pref_.save(&this->linked_lock_info_);
  global_preferences->sync();
  this->publish_text_or_unlinked_(this->keypad_text_sensor_, nullptr);
  this->lock_linked_ = false;
  this->pairing_ui_.set_lock_linked(false);
  this->publish_linked_lock_();
  this->clear_lock_battery_();
  this->keypad_paired_ = false;
  this->pairing_ui_.set_keypad_paired(false);
  this->pairing_ui_.set_keypad_family(KeypadFamily::ORIGINAL);
  this->reset_battery_sensor_(this->keypad_battery_level_sensor_,
                              this->last_keypad_battery_);

  // Invalidate any in-flight BLE session — it is keyed to the old secret —
  // and forget the learned token slot along with it.
  this->session_.reset();
  this->session_.forget_slot();
  this->keypad_state_.rearm();

  // Re-enter setup mode straight away with the rotated key.
  this->pairing_ui_.set_shared_key(this->shared_key_);
  if (this->pairing_ui_.start()) {
    ESP_LOGI(TAG, "Reset complete — re-entering setup mode");
  } else {
    ESP_LOGW(TAG, "Setup UI failed to start; check port 80 is free");
  }
}

void ResetButton::press_action() {
  if (this->parent_->is_pairing_active()) {
    ESP_LOGW(TAG, "Setup wizard is already active, ignoring Reset action");
    return;
  }
  this->parent_->reset_pairing();
}

void SwitchbotKeypadBridge::rearm() {
  this->keypad_state_.rearm();
  ESP_LOGI(TAG, "Reporting locked state on the next keypad poll (rearm)");
}

bool SwitchbotKeypadBridge::run_crypto_selftest() {
  const uint8_t key[16]{};
  const uint8_t nonce[12]{};
  const uint8_t plaintext[16]{};
  const uint8_t expected_ciphertext[16] = {
      0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92,
      0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78};
  const uint8_t expected_tag[16] = {
      0xAB, 0x6E, 0x47, 0xD4, 0x2C, 0xEC, 0x13, 0xBD,
      0xF5, 0x3A, 0x67, 0xB2, 0x12, 0x57, 0xBD, 0xDF};
  uint8_t ciphertext[16]{};
  uint8_t tag[16]{};
  uint8_t recovered[16]{};
  const bool ok =
      aes_gcm_encrypt_raw_key(key, nonce, plaintext, ciphertext, sizeof(plaintext), tag) &&
      std::memcmp(ciphertext, expected_ciphertext, sizeof(ciphertext)) == 0 &&
      std::memcmp(tag, expected_tag, sizeof(tag)) == 0 &&
      aes_gcm_decrypt_raw_key(key, nonce, expected_ciphertext, recovered, sizeof(recovered)) &&
      std::memcmp(recovered, plaintext, sizeof(plaintext)) == 0;
  if (ok) {
    ESP_LOGI(TAG, "GCM primitive self-test: PASS (ciphertext/full tag/decrypt known-answer vector)");
  } else {
    ESP_LOGE(TAG, "GCM primitive self-test: FAIL");
  }
  const uint8_t prefix[2] = {expected_tag[0], expected_tag[1]};
  const uint8_t wrong_prefix[2] = {static_cast<uint8_t>(prefix[0] ^ 1), prefix[1]};
  uint8_t altered_ciphertext[sizeof(expected_ciphertext)];
  std::memcpy(altered_ciphertext, expected_ciphertext, sizeof(altered_ciphertext));
  altered_ciphertext[0] ^= 1;
  const uint8_t zeros[sizeof(recovered)]{};
  const auto rejects_and_clears = [&](const uint8_t *input, const uint8_t (&received)[2]) {
    std::memset(recovered, 0xFF, sizeof(recovered));
    return !aes_gcm_decrypt_verify_prefix(key, nonce, input, recovered, sizeof(recovered), received) &&
           std::memcmp(recovered, zeros, sizeof(recovered)) == 0;
  };
  const bool prefix_ok =
      aes_gcm_decrypt_verify_prefix(key, nonce, expected_ciphertext, recovered, sizeof(recovered), prefix) &&
      std::memcmp(recovered, plaintext, sizeof(plaintext)) == 0 &&
      rejects_and_clears(expected_ciphertext, wrong_prefix) &&
      rejects_and_clears(altered_ciphertext, prefix);
  if (prefix_ok) {
    ESP_LOGI(TAG, "GCM tag-prefix self-test: PASS (valid tag accepted, altered tag and ciphertext rejected)");
  } else {
    ESP_LOGE(TAG, "GCM tag-prefix self-test: FAIL");
  }
  return ok && prefix_ok;
}

void SwitchbotKeypadBridge::update_rearm_timer_() {
  if (this->keypad_state_.update(millis())) {
    ESP_LOGI(TAG, "Face/palm rearm timer expired; reporting locked state on the next keypad poll");
  }
}

void SwitchbotKeypadBridge::dump_config() {
  ESP_LOGCONFIG(TAG, "SwitchBot Keypad Bridge:");
  ESP_LOGCONFIG(TAG, "  BLE address: %s", NimBLEDevice::getAddress().toString().c_str());
  ESP_LOGCONFIG(TAG, "  Setup UI: port 80");
  ESP_LOGCONFIG(TAG, "  Face/palm rearm after: %ums (0 = disabled)",
                static_cast<unsigned>(this->keypad_state_.rearm_after()));
  ESP_LOGCONFIG(TAG, "  Physical lock relay: %s",
                this->lock_linked_ ? this->linked_lock_info_.name : "Unlinked");
  if (this->keypad_battery_level_sensor_ != nullptr ||
      this->lock_battery_level_sensor_ != nullptr) {
    ESP_LOGCONFIG(TAG, "  Battery refresh interval: %us",
                  static_cast<unsigned>(this->battery_scan_interval_ms_ / 1000));
  }
  if (this->is_failed()) {
    ESP_LOGE(TAG, "  Initialization failed - see previous errors");
  }
}

void SwitchbotKeypadBridge::create_shared_key_() {
  esp_fill_random(this->shared_key_.data(), this->shared_key_.size());
  this->shared_key_pref_.save(&this->shared_key_);
  global_preferences->sync();
}

bool SwitchbotKeypadBridge::import_aes_key_() {
  // Drop any previously imported handle so the slot can be re-keyed in
  // place — reset_pairing() rotates the key without rebooting.
  if (this->aes_key_handle_ != PSA_KEY_ID_NULL) {
    psa_destroy_key(this->aes_key_handle_);
    this->aes_key_handle_ = PSA_KEY_ID_NULL;
  }

  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
  psa_set_key_algorithm(&attrs, PSA_ALG_CTR);
  psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attrs, 128);
  psa_status_t status = psa_import_key(&attrs, this->shared_key_.data(), AES_KEY_SIZE,
                                       &this->aes_key_handle_);
  psa_reset_key_attributes(&attrs);

  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "AES key import failed (%d)", static_cast<int>(status));
    return false;
  }
  this->session_.set_aes_key(this->aes_key_handle_);
  return true;
}

bool SwitchbotKeypadBridge::prepare_keys_() {
  psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    ESP_LOGE(TAG, "PSA Crypto init failed (%d)", static_cast<int>(status));
    return false;
  }
  return this->import_aes_key_();
}

bool SwitchbotKeypadBridge::prepare_ble_() {
  // Spoof a SwitchBot-OUI BLE address: keep the chip-unique tail, replace
  // the leading three bytes. The Vision keypad filters scan results on this
  // prefix and would otherwise ignore the bridge. Must run before NimBLE
  // init so the controller picks up the patched base MAC.
  uint8_t base[6];
  esp_err_t err = esp_efuse_mac_get_default(base);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "esp_efuse_mac_get_default failed (err=0x%X)", err);
    return false;
  }
  std::memcpy(base, SPOOFED_OUI, sizeof(SPOOFED_OUI));
  err = esp_base_mac_addr_set(base);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "esp_base_mac_addr_set failed (err=0x%X)", err);
    return false;
  }
  ESP_LOGD(TAG, "Base MAC set to %02X:%02X:%02X:%02X:%02X:%02X (SwitchBot OUI spoof)",
           base[0], base[1], base[2], base[3], base[4], base[5]);

  NimBLEDevice::init("WoLock");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);

  this->server_ = NimBLEDevice::createServer();
  this->server_->setCallbacks(new ServerCallbacks(this));

  NimBLEService *service = this->server_->createService(SWITCHBOT_SERVICE_UUID);
  this->tx_characteristic_ =
      service->createCharacteristic(SWITCHBOT_TX_CHAR_UUID, NIMBLE_PROPERTY::NOTIFY);
  NimBLECharacteristic *rx = service->createCharacteristic(
      SWITCHBOT_RX_CHAR_UUID, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR);
  rx->setCallbacks(new RxCharCallbacks(this));

  NimBLEAdvertising *advertising = NimBLEDevice::getAdvertising();
  advertising->addServiceUUID(service->getUUID());
  advertising->setManufacturerData(
      std::string(reinterpret_cast<const char *>(ADVERTISING_MFG_DATA), sizeof(ADVERTISING_MFG_DATA)));
  advertising->start();
  return true;
}

// ---------------------------------------------------------------------------
// RX path
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::update_keypad_gcm_probe_() {
  if (!this->gcm_diagnostics_ || this->keypad_gcm_experimental_)
    return;
  const uint32_t now = millis();
  if (this->keypad_gcm_probe_active_ && now - this->keypad_gcm_probe_started_ >= 30000) {
    this->keypad_gcm_probe_active_ = false;
    this->keypad_gcm_probe_slot_ = 0;
    this->session_.reset();
    const auto stage = this->keypad_gcm_probe_stage_;
    const char *result = stage == KeypadGcmProbeStage::FIRST_FRAME ? "first frame not received"
                         : stage == KeypadGcmProbeStage::WAIT_POLL ? "follow-up not received"
                         : stage == KeypadGcmProbeStage::AFTER_POLL_REPLY ? "no third frame observed"
                                                                        : "frame checks finished";
    ESP_LOGI(TAG, "Keypad GCM probe ended: %s; next session uses CTR", result);
  }
  if (this->pairing_ui_.take_keypad_probe_request() && !this->keypad_gcm_probe_active_ &&
      this->keypad_paired_ && !this->lock_linked_ && !this->is_failed()) {
    this->keypad_gcm_probe_active_ = true;
    this->keypad_gcm_probe_started_ = now;
    this->keypad_gcm_probe_slot_ = 0;
    this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::FIRST_FRAME;
    this->session_.reset();
    ESP_LOGI(TAG, "Keypad GCM probe armed for 30 seconds; keypad actions suspended");
  }
}

void SwitchbotKeypadBridge::reject_keypad_gcm_exchange_() {
  this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::FINISHED;
  this->keypad_gcm_command_ = {};
  if (this->keypad_gcm_experimental_) {
    if (this->keypad_gcm_failures_ == 0)
      this->keypad_gcm_failures_since_ = millis();
    if (++this->keypad_gcm_failures_ == GCM_FAILURE_LIMIT) {
      ESP_LOGW(TAG, "GCM experimental rejection limit reached; waiting for the failure window to expire");
    }
  }
}

void SwitchbotKeypadBridge::inspect_keypad_gcm_frame_(const std::string &frame, uint16_t connection) {
  const auto stage = this->keypad_gcm_probe_stage_;
  if (stage == KeypadGcmProbeStage::HOLD_POLL_REPLY) {
    if (this->withhold_this_poll_reply_) {
      ESP_LOGI(TAG, "Poll hold: additional frame at +%u ms; control still withholding",
               unsigned(millis() - this->poll_hold_started_));
      return;
    }
    this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::FINISHED;
    ESP_LOGI(TAG, "Poll hold: additional keypad frame at +%u ms; reply cancelled",
             unsigned(millis() - this->poll_hold_started_));
    return;
  }
  if (stage == KeypadGcmProbeStage::FINISHED)
    return;
  const auto *wire = reinterpret_cast<const uint8_t *>(frame.data());
  if (frame.size() == 8 && LockSession::is_iv_request(frame)) {
    if (stage != KeypadGcmProbeStage::FIRST_FRAME) {
      this->reject_keypad_gcm_exchange_();
      ESP_LOGI(TAG, "Keypad GCM probe: keypad requested a new handshake after a diagnostic reply");
      return;
    }
    if (wire[7] != SHARED_SLOT_ORIGINAL) {
      ESP_LOGW(TAG, "Keypad GCM probe: skipping a session request outside the Touch test slot");
      return;
    }
    auto &reply = this->keypad_gcm_probe_reply_;
    if (this->keypad_gcm_probe_slot_ == 0) {
      // Client reference header and three observed 20-byte GCM lock replies
      // with all-zero trailers. This profile is only for the experiment.
      reply = {0x01, 0x00, 0x01, 0x00};
      esp_fill_random(reply.data() + 4, 12);
      this->keypad_gcm_probe_slot_ = wire[7];
    }
    if (!this->tx_characteristic_->notify(reply.data(), reply.size(), connection)) {
      this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::FINISHED;
      ESP_LOGW(TAG, "Keypad GCM: session announcement could not be sent");
      return;
    }
    ESP_LOGI(TAG, "Keypad GCM probe: advertised mode=0x01 length=20 trailer=all-zero");
    return;
  }
  if (this->keypad_gcm_probe_slot_ == 0 || frame.size() <= LockSession::HEADER_LEN ||
      frame.size() > LockSession::MAX_PACKET || wire[0] != 0x57 ||
      wire[1] != this->keypad_gcm_probe_slot_) {
    if (this->keypad_gcm_experimental_ && this->keypad_gcm_probe_slot_ != 0) {
      this->reject_keypad_gcm_exchange_();
      ESP_LOGW(TAG, "GCM experimental exchange rejected: invalid frame envelope");
    }
    return;
  }
  if (this->keypad_gcm_experimental_ &&
      ((stage == KeypadGcmProbeStage::FIRST_FRAME && frame.size() != 12) ||
       (stage == KeypadGcmProbeStage::WAIT_POLL && frame.size() != 8))) {
    this->reject_keypad_gcm_exchange_();
    ESP_LOGW(TAG, "GCM experimental exchange rejected: unexpected frame length");
    return;
  }
  const uint8_t prefix[2] = {wire[2], wire[3]};
  std::array<uint8_t, 12> initial_nonce;
  std::memcpy(initial_nonce.data(), this->keypad_gcm_probe_reply_.data() + 4, initial_nonce.size());
  auto check_at = [&](const std::array<uint8_t, 12> &nonce, DecodedCommand &command, uint8_t *poll_suffix = nullptr) {
    uint8_t scratch[LockSession::MAX_PAYLOAD];
    const size_t length = frame.size() - LockSession::HEADER_LEN;
    const bool match = aes_gcm_decrypt_verify_prefix(this->shared_key_.data(), nonce.data(),
        wire + LockSession::HEADER_LEN, scratch, length, prefix);
    command = match ? decode_lock_command(scratch, length) : DecodedCommand{};
    if (poll_suffix != nullptr && command.type == CommandType::STATE_POLL) {
      *poll_suffix = scratch[3];  // Valid state polls have four bytes.
    }
    mbedtls_platform_zeroize(scratch, sizeof(scratch));
    return match;
  };
  std::array<std::array<uint8_t, 12>, 4> nonces{initial_nonce};
  for (size_t i = 1; i < nonces.size(); ++i) {
    nonces[i] = nonces[i - 1];
    if (!advance_gcm_probe_nonce(nonces[i])) {
      this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::FINISHED;
      ESP_LOGW(TAG, "Keypad GCM probe: nonce counter overflow");
      return;
    }
  }

  auto send_reply = [&](const std::array<uint8_t, 12> &nonce, const uint8_t *payload, size_t length) {
    uint8_t response[LockSession::MAX_PACKET] = {0x01, wire[1]};
    uint8_t tag[16];
    if (!aes_gcm_encrypt_raw_key(this->shared_key_.data(), nonce.data(), payload,
                                response + LockSession::HEADER_LEN, length, tag)) {
      return false;
    }
    response[2] = tag[0];
    response[3] = tag[1];
    if (this->gcm_empty_ack_test_ && stage == KeypadGcmProbeStage::WAIT_POLL) {
      if (LockSession::HEADER_LEN + length != this->held_poll_reply_.size()) return false;
      std::memcpy(this->held_poll_reply_.data(), response, this->held_poll_reply_.size());
      this->poll_hold_started_ = millis();
      this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::HOLD_POLL_REPLY;
      this->withhold_this_poll_reply_ = !this->withhold_this_poll_reply_;
      ESP_LOGI(TAG, "Poll hold: start at +0 ms; %s",
               this->withhold_this_poll_reply_ ? "control: no reply this session" : "waiting 2000 ms");
      return true;
    }
    if (!this->tx_characteristic_->notify(response, LockSession::HEADER_LEN + length, connection)) {
      ESP_LOGW(TAG, "Keypad GCM: could not send encrypted reply");
      return false;
    }
    return true;
  };

  if (stage == KeypadGcmProbeStage::AFTER_POLL_REPLY) {
    DecodedCommand command;
    const bool plus_two = check_at(nonces[2], command);
    const bool plus_three = check_at(nonces[3], command);
    ESP_LOGI(TAG, "Keypad GCM probe: third frame length=%zu N+2=%s N+3=%s",
             frame.size(), plus_two ? "match" : "no", plus_three ? "match" : "no");
    this->reject_keypad_gcm_exchange_();
    return;
  }

  DecodedCommand initial_command;
  const bool match = check_at(initial_nonce, initial_command);
  if (stage == KeypadGcmProbeStage::WAIT_POLL) {
    DecodedCommand plus_one_command, plus_two_command;
    uint8_t poll_suffix = 0;
    const bool plus_one = check_at(nonces[1], plus_one_command, &poll_suffix);
    const bool plus_two = check_at(nonces[2], plus_two_command);
    ESP_LOGI(TAG, "Keypad GCM probe: follow-up length=%zu N=%s N+1=%s N+2=%s poll_at_N+1=%s poll_at_N+2=%s",
             frame.size(), match ? "match" : "no", plus_one ? "match" : "no",
             plus_two ? "match" : "no", plus_one_command.type == CommandType::STATE_POLL ? "yes" : "no",
             plus_two_command.type == CommandType::STATE_POLL ? "yes" : "no");
    this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::FINISHED;
    if (plus_one && plus_one_command.type == CommandType::STATE_POLL && !match && !plus_two) {
      if (this->gcm_diagnostics_) {
        this->pairing_ui_.record_keypad_poll_suffix(poll_suffix);
        ESP_LOGI(TAG, "Keypad GCM: captured state poll format for lock comparison");
      }
      uint8_t state_payload[1 + sizeof(STATE_PAYLOAD_TAIL)];
      const auto state = this->keypad_gcm_command_.type == CommandType::LOCK
                            ? KeypadState::LockState::LOCKED : KeypadState::LockState::UNLOCKED;
      state_payload[0] = static_cast<uint8_t>(state);
      std::memcpy(state_payload + 1, STATE_PAYLOAD_TAIL, sizeof(STATE_PAYLOAD_TAIL));
      if (this->keypad_gcm_reference_active_) {
        static_assert(sizeof(state_payload) == std::tuple_size<decltype(this->keypad_gcm_reference_state_)>::value);
        std::memcpy(state_payload, this->keypad_gcm_reference_state_.data(), sizeof(state_payload));
        ESP_LOGI(TAG, "Keypad GCM: using genuine lock poll payload at nonce=N+3");
      }
      if (this->gcm_native_reply_test_) {
        // Fixed diagnostic snapshot from the successful native fingerprint exchange.
        const uint8_t native_state[] = {0x94, 0x08, 0x86, 0x56, 0, 0, 0, 0, 0x40, 0x09, 0x05, 0, 0, 0};
        static_assert(sizeof(native_state) == sizeof(state_payload));
        std::memcpy(state_payload, native_state, sizeof(native_state));
      }
      if (send_reply(nonces[this->gcm_native_reply_test_ ? 1 : 3], state_payload, sizeof(state_payload))) {
        if (this->keypad_gcm_probe_stage_ == KeypadGcmProbeStage::HOLD_POLL_REPLY) return;
        this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::AFTER_POLL_REPLY;
        ESP_LOGI(TAG, "Keypad GCM probe: sent poll reply nonce=N+%u", this->gcm_native_reply_test_ ? 1U : 3U);
      }
    } else {
      this->reject_keypad_gcm_exchange_();
    }
    return;
  }
  ESP_LOGI(TAG, "Keypad GCM probe: first frame length=%zu tag_prefix=%s nonce=initial",
           frame.size(), match ? "match" : "mismatch");
  this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::FINISHED;
  if (!match) {
    this->reject_keypad_gcm_exchange_();
    ESP_LOGW(TAG, "Keypad GCM: rejected first frame because its tag did not match");
    return;
  }
  const auto method = initial_command.method;
  const bool lock = initial_command.type == CommandType::LOCK;
  const bool touch_unlock = initial_command.type == CommandType::UNLOCK &&
      (method == UnlockMethod::FINGERPRINT || method == UnlockMethod::NFC || method == UnlockMethod::PIN);
  if (this->keypad_gcm_reference_active_ &&
      (initial_command.type != CommandType::UNLOCK || method != UnlockMethod::FINGERPRINT)) {
    ESP_LOGI(TAG, "Keypad GCM reference test expects a fingerprint unlock");
    return;
  }
  if (!touch_unlock && !lock) {
    ESP_LOGI(TAG, "Keypad GCM: valid tag but unsupported Touch command");
    return;
  }

  const uint8_t *response = lock ? RESPONSE_LOCK : RESPONSE_UNLOCK;
  size_t response_length = lock ? sizeof(RESPONSE_LOCK) : sizeof(RESPONSE_UNLOCK);
  const uint8_t native_unlock[] = {0x9E, 0xA4, 0x7F, 0x7F, 0x00};
  if (this->gcm_native_reply_test_) {
    if (!touch_unlock || method != UnlockMethod::FINGERPRINT) return;
    response = native_unlock;
    response_length = sizeof(native_unlock);
  }
  if (this->gcm_empty_ack_test_) {
    if (!touch_unlock || method != UnlockMethod::FINGERPRINT) return;
    response_length = 0;
  }
  if (send_reply(nonces[this->gcm_native_reply_test_ ? 0 : 2], response, response_length)) {
    this->keypad_gcm_command_ = initial_command;
    this->keypad_gcm_probe_stage_ = KeypadGcmProbeStage::WAIT_POLL;
    if (this->gcm_empty_ack_test_) {
      ESP_LOGI(TAG, "Keypad GCM empty ACK sent: wire_bytes=4 payload_bytes=0 tag=computed");
    }
    ESP_LOGI(TAG, "Keypad GCM: sent %s reply nonce=N+%u", lock ? "lock" : "unlock",
             this->gcm_native_reply_test_ ? 0U : 2U);
  }
}

void SwitchbotKeypadBridge::on_rx_frame_(const std::string &frame, uint16_t connection) {
  if (this->keypad_gcm_experimental_) {
    const uint32_t now = millis();
    if (this->keypad_gcm_failures_ != 0 && now - this->keypad_gcm_failures_since_ >= GCM_FAILURE_WINDOW_MS) {
      this->keypad_gcm_failures_ = 0;
    }
    if (this->keypad_paired_ && !this->lock_linked_ && connection == this->keypad_gcm_connection_ &&
        now - this->keypad_gcm_connection_started_ < GCM_EXCHANGE_TIMEOUT_MS &&
        this->keypad_gcm_failures_ < GCM_FAILURE_LIMIT) {
      this->inspect_keypad_gcm_frame_(frame, connection);
    }
    return;
  }
  if (this->keypad_gcm_probe_active_) {
    this->inspect_keypad_gcm_frame_(frame, connection);
    return;
  }
  switch (this->session_.process_frame(frame)) {
    case LockSession::Action::SEND_IV:
      this->notify_(this->session_.iv_response(), this->session_.iv_response_size());
      return;
    case LockSession::Action::COMMAND:
      this->handle_command_(this->session_.header(), this->session_.command());
      return;
    case LockSession::Action::NONE:
    default:
      return;  // dropped — the session logged why
  }
}

void SwitchbotKeypadBridge::handle_command_(const FrameHeader &header, const DecodedCommand &command) {
  // Publish decoded Home Assistant events immediately: the event reports the
  // keypad action itself, so automations must not wait for the physical
  // lock's BLE round-trip (which runs in parallel below).
  switch (command.type) {
    case CommandType::LOCK:
      ESP_LOGI(TAG, "Lock");
      this->keypad_state_.rearm();
      this->publish_lock_();
      break;

    case CommandType::UNLOCK:
      ESP_LOGI(TAG, "Unlock: method=%s (0x%02X) index=%d",
               unlock_method_name(command.method),
               static_cast<uint8_t>(command.method), command.credential_index);
      // Start before callbacks so an on_unlock automation can rearm explicitly.
      this->keypad_state_.unlock(millis());
      this->publish_unlock_(command.method, command.credential_index);
      break;

    case CommandType::STATE_POLL:
      ESP_LOGV(TAG, "State poll");
      break;

    case CommandType::DOORBELL:
      ESP_LOGI(TAG, "Doorbell");
      this->publish_doorbell_();
      break;

    case CommandType::UNKNOWN:
    default:
      break;
  }

  // With a physical lock linked, answer the keypad exactly like standalone
  // mode and mirror side-effecting payloads onto the lock in the background.
  // The keypad must never wait for, or receive, the physical lock's reply.
  if (this->lock_linked_) {
    this->send_local_response_(header, command);
    switch (command.type) {
      case CommandType::LOCK:
      case CommandType::UNLOCK:
        if (!this->relay_to_lock_async_(header, command)) {
          ESP_LOGW(TAG, "Physical lock relay unavailable after local keypad response");
        }
        return;
      case CommandType::STATE_POLL:
      case CommandType::DOORBELL:
      default:
        return;
    }
  }

  // Local answer only when no physical lock is linked.
  this->send_local_response_(header, command);
}

// Answer the keypad locally. Linked-lock mode uses the same path; the lock's
// eventual reply is logged but never forwarded back to the keypad.
void SwitchbotKeypadBridge::send_local_response_(const FrameHeader &header,
                                                 const DecodedCommand &command) {
  switch (command.type) {
    case CommandType::LOCK:
      this->send_encrypted_response_(header, RESPONSE_LOCK, sizeof(RESPONSE_LOCK));
      return;
    case CommandType::UNLOCK:
      this->send_encrypted_response_(header, RESPONSE_UNLOCK, sizeof(RESPONSE_UNLOCK));
      return;
    case CommandType::STATE_POLL:
      this->handle_state_poll_(header);
      return;
    case CommandType::DOORBELL:
      this->send_ack_(header);
      return;
    case CommandType::UNKNOWN:
    default:
      this->send_ack_(header);
      return;
  }
}

void SwitchbotKeypadBridge::handle_state_poll_(const FrameHeader &header) {
  this->update_rearm_timer_();
  uint8_t state_payload[1 + sizeof(STATE_PAYLOAD_TAIL)];
  state_payload[0] = static_cast<uint8_t>(this->keypad_state_.lock_state());
  std::memcpy(state_payload + 1, STATE_PAYLOAD_TAIL, sizeof(STATE_PAYLOAD_TAIL));
  this->send_encrypted_response_(header, state_payload, sizeof(state_payload));
}

PhysicalLockClient::Config SwitchbotKeypadBridge::physical_lock_config_(uint8_t slot_id) const {
  PhysicalLockClient::Config cfg;
  cfg.mac = "";
  if (this->linked_lock_info_.valid != 0) {
    char mac[18];
    std::snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                  this->linked_lock_info_.mac[0], this->linked_lock_info_.mac[1],
                  this->linked_lock_info_.mac[2], this->linked_lock_info_.mac[3],
                  this->linked_lock_info_.mac[4], this->linked_lock_info_.mac[5]);
    cfg.mac = mac;
    cfg.model = static_cast<PhysicalLockModel>(this->linked_lock_info_.model);
    cfg.key_id = slot_id;
    cfg.key = this->shared_key_;
  }
  return cfg;
}

bool SwitchbotKeypadBridge::relay_to_lock_async_(const FrameHeader &header,
                                                 const DecodedCommand &command) {
  if (command.type != CommandType::LOCK && command.type != CommandType::UNLOCK) {
    ESP_LOGW(TAG, "Cannot relay unsupported keypad command");
    return false;
  }
  if (this->session_.plaintext_size() == 0) {
    ESP_LOGW(TAG, "Cannot relay command: no decrypted keypad plaintext");
    return false;
  }
  if (this->lock_relay_busy_.exchange(true)) {
    ESP_LOGW(TAG, "Lock relay still in flight — answering this command locally");
    return false;
  }
  // The relay opens a central connection; make sure the battery advert scan
  // isn't holding the radio.
  this->stop_battery_scan_();

  // Snapshot everything the task needs now: the session buffer is reused by
  // the next keypad frame, and the config must not be read off-thread.
  struct RelayCtx {
    SwitchbotKeypadBridge *self;
    PhysicalLockClient::Config cfg;
    std::vector<uint8_t> plaintext;
    DecodedCommand command;
  };
  auto *ctx = new RelayCtx{
      this, this->physical_lock_config_(header.key_id),
      {this->session_.plaintext(),
       this->session_.plaintext() + this->session_.plaintext_size()},
      command};

  BaseType_t rc = xTaskCreatePinnedToCore(
      [](void *raw) {
        auto *c = static_cast<RelayCtx *>(raw);
        std::vector<uint8_t> response;
        std::string error;
        bool result_posted = false;
        auto post_relay_result = [c, &result_posted](bool ok) {
          c->self->relay_command_  = c->command;
          c->self->relay_ok_       = ok;
          c->self->pending_relay_apply_.store(true, std::memory_order_release);
          result_posted = true;
        };
        const bool ok = c->self->physical_lock_client_.send_plaintext(
            c->cfg, c->plaintext.data(), c->plaintext.size(), response, error,
            nullptr,
            [&post_relay_result](const std::vector<uint8_t> &reply) {
              // The keypad already got its local response. This callback only
              // lets loop() log that the physical lock replied.
              (void) reply;
              post_relay_result(true);
            });
        if (!ok) {
          ESP_LOGW(TAG, "Lock relay command failed: %s", error.c_str());
        }
        // If the lock never produced a response, hand the final outcome to
        // loop() after send_plaintext() returns. Successful replies are noted
        // immediately by the callback above.
        if (!result_posted) {
          post_relay_result(ok);
        }
        c->self->lock_relay_busy_.store(false);
        delete c;
        vTaskDelete(nullptr);
      },
      "lock-relay", 8192, ctx, tskIDLE_PRIORITY + 2, nullptr,
      // Same core as the BT task, matching the pairer/linker jobs.
      0);
  if (rc != pdPASS) {
    delete ctx;
    this->lock_relay_busy_.store(false);
    ESP_LOGW(TAG, "Could not start the lock relay task");
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::send_ack_(const FrameHeader &header) {
  const uint8_t ack[LockSession::HEADER_LEN] = {0x01, header.key_id, header.seq_a, header.seq_b};
  ESP_LOGD(TAG, "Keypad TX: mode=ctr kind=ack length=%zu", sizeof(ack));
  this->notify_(ack, sizeof(ack));
}

void SwitchbotKeypadBridge::send_encrypted_response_(const FrameHeader &header,
                                                    const uint8_t *plaintext, size_t length) {
  uint8_t packet[LockSession::MAX_PACKET];
  const size_t n = this->session_.encrypt_response(header, plaintext, length, packet);
  if (n == 0) {
    return;  // error already logged
  }
  ESP_LOGD(TAG, "Keypad TX: mode=ctr kind=encrypted length=%zu", n);
  this->notify_(packet, n);
}

void SwitchbotKeypadBridge::notify_(const uint8_t *data, size_t length) {
  this->tx_characteristic_->setValue(data, length);
  this->tx_characteristic_->notify();
}

// ---------------------------------------------------------------------------
// Eventing
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::publish_lock_() {
  if (this->keypad_event_ != nullptr) {
    this->keypad_event_->trigger("Lock");
  }
  this->on_lock_callbacks_.call();
}

void SwitchbotKeypadBridge::publish_unlock_(UnlockMethod method, int index) {
  const char *method_str = unlock_method_name(method);
  if (this->keypad_event_ != nullptr) {
    this->keypad_event_->trigger("Unlock");
  }
  this->on_unlock_callbacks_.call(std::string(method_str), index);
}

void SwitchbotKeypadBridge::publish_doorbell_() {
  if (this->keypad_event_ != nullptr) {
    this->keypad_event_->trigger("Doorbell");
  }
  this->on_doorbell_callbacks_.call();
}

void SwitchbotKeypadBridge::publish_linked_lock_() {
  if (this->lock_linked_ && this->linked_lock_info_.valid != 0 &&
      this->linked_lock_info_.name[0] != '\0') {
    this->publish_text_or_unlinked_(this->linked_lock_text_sensor_,
                                    this->linked_lock_info_.name);
  } else {
    this->publish_text_or_unlinked_(this->linked_lock_text_sensor_, nullptr);
  }
}

void SwitchbotKeypadBridge::save_and_sync_(ESPPreferenceObject &pref,
                                           const KeypadInfo *value) {
  pref.save(value);
  global_preferences->sync();
}

void SwitchbotKeypadBridge::save_and_sync_(ESPPreferenceObject &pref,
                                           const LinkedLockInfo *value) {
  pref.save(value);
  global_preferences->sync();
}

void SwitchbotKeypadBridge::publish_text_or_unlinked_(
    text_sensor::TextSensor *sensor, const char *value) {
  if (sensor == nullptr) {
    return;
  }
  sensor->publish_state((value != nullptr && value[0] != '\0') ? value : "Unlinked");
}

void SwitchbotKeypadBridge::publish_battery_if_changed_(
    sensor::Sensor *sensor, int value, int &last, const char *label) {
  ESP_LOGD(TAG, "%s battery: %d%%", label, value);
  if (sensor != nullptr && value != last) {
    last = value;
    sensor->publish_state(static_cast<float>(value));
  }
}

void SwitchbotKeypadBridge::reset_battery_sensor_(sensor::Sensor *sensor,
                                                  int &last) {
  last = -1;
  if (sensor != nullptr) {
    sensor->publish_state(NAN);
  }
}

// ---------------------------------------------------------------------------
// Battery refresh (advertisement scan)
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::maybe_start_battery_scan_() {
  const uint32_t now = millis();

  if (this->battery_scan_active_.load(std::memory_order_acquire)) {
    // NimBLE drops isScanning() when the window elapses or stop() ran.
    if (!NimBLEDevice::getScan()->isScanning()) {
      this->stop_battery_scan_();
      this->next_battery_scan_at_ = now + this->battery_scan_interval_ms_;
    }
    return;
  }

  if (static_cast<int32_t>(now - this->next_battery_scan_at_) < 0) {
    return;
  }

  const bool wants_keypad =
      this->keypad_battery_level_sensor_ != nullptr && this->keypad_paired_;
  const bool wants_lock = this->lock_battery_level_sensor_ != nullptr &&
                          this->lock_linked_ &&
                          this->linked_lock_info_.valid != 0;
  if (!wants_keypad && !wants_lock) {
    this->next_battery_scan_at_ = now + BATTERY_SCAN_RETRY_MS;
    return;
  }

  // The scan singleton is shared with the pairing flows (which run blocking
  // scans), and the keypad does not advertise while it holds a connection to
  // us — defer rather than fight either.
  if (this->background_ble_busy_() ||
      NimBLEDevice::getScan()->isScanning()) {
    this->next_battery_scan_at_ = now + BATTERY_SCAN_RETRY_MS;
    return;
  }

  this->battery_scan_wants_keypad_ = wants_keypad;
  this->battery_scan_wants_lock_ = wants_lock;
  this->keypad_battery_scan_found_ = false;
  this->lock_battery_scan_found_ = false;
  this->battery_scan_keypad_known_ = this->keypad_info_.valid != 0;
  if (this->battery_scan_keypad_known_) {
    std::memcpy(this->battery_scan_keypad_mac_, this->keypad_info_.mac,
                sizeof(this->battery_scan_keypad_mac_));
    this->battery_scan_keypad_family_ = this->keypad_info_.family;
  }
  if (wants_lock) {
    std::memcpy(this->battery_scan_lock_mac_, this->linked_lock_info_.mac,
                sizeof(this->battery_scan_lock_mac_));
    this->battery_scan_lock_model_ =
        static_cast<PhysicalLockModel>(this->linked_lock_info_.model);
  } else {
    this->battery_scan_lock_model_ = PhysicalLockModel::UNKNOWN;
  }

  NimBLEScan *scan = NimBLEDevice::getScan();
  scan->setScanCallbacks(this->battery_scan_callbacks_, false);
  configure_switchbot_scan(scan);
  this->battery_scan_active_.store(true, std::memory_order_release);
  if (scan->start(BATTERY_SCAN_DURATION_MS, false, true)) {
    ESP_LOGD(TAG, "Battery scan window opened (%u ms)",
             static_cast<unsigned>(BATTERY_SCAN_DURATION_MS));
  } else {
    ESP_LOGW(TAG, "Battery scan failed to start");
    this->stop_battery_scan_();
    this->next_battery_scan_at_ = now + BATTERY_SCAN_RETRY_MS;
  }
}

void SwitchbotKeypadBridge::handle_battery_advert_(const NimBLEAdvertisedDevice *adv) {
  // The callbacks stay registered on the shared scan singleton, so pairing
  // scans fire them too — only act inside our own scan window.
  if (!this->battery_scan_active_.load(std::memory_order_acquire)) {
    return;
  }

  const std::array<uint8_t, 6> mac = addr_bytes(adv->getAddress());
  const std::vector<uint8_t> sd = switchbot_service_data(adv);

  std::string mfr;
  if (adv->haveManufacturerData()) {
    mfr = adv->getManufacturerData();
  }

  if (this->battery_scan_wants_keypad_ && !this->keypad_battery_scan_found_) {
    bool keypad_match = false;
    KeypadFamily family = KeypadFamily::ORIGINAL;
    if (this->battery_scan_keypad_known_) {
      keypad_match =
          std::memcmp(mac.data(), this->battery_scan_keypad_mac_, mac.size()) == 0;
      family = static_cast<KeypadFamily>(this->battery_scan_keypad_family_);
    } else {
      // Keypad linked before the MAC was persisted: adopt the first advert
      // matching a known keypad signature (loop() persists it).
      const KeypadIdent ident = identify_keypad(sd.data(), sd.size());
      keypad_match = ident.is_keypad;
      family = ident.family;
    }

    if (keypad_match) {
      const int battery = parse_keypad_battery(
          family, sd.data(), sd.size(),
          reinterpret_cast<const uint8_t *>(mfr.data()), mfr.size());
      if (battery >= 0) {
        std::lock_guard<std::mutex> lk(this->rx_mutex_);
        this->keypad_battery_advert_value_ = battery;
        std::memcpy(this->keypad_battery_advert_mac_, mac.data(), mac.size());
        this->keypad_battery_advert_family_ = static_cast<uint8_t>(family);
        this->keypad_battery_advert_pending_ = true;
      }
    }
  }

  if (this->battery_scan_wants_lock_ && !this->lock_battery_scan_found_ &&
      std::memcmp(mac.data(), this->battery_scan_lock_mac_, mac.size()) == 0) {
    const std::vector<uint8_t> mfr_payload = switchbot_manufacturer_payload(adv);
    const int battery = parse_lock_battery(
        this->battery_scan_lock_model_, sd.data(), sd.size(),
        mfr_payload.data(), mfr_payload.size());
    if (battery >= 0) {
      std::lock_guard<std::mutex> lk(this->rx_mutex_);
      this->lock_battery_advert_value_ = battery;
      this->lock_battery_advert_pending_ = true;
    }
  }
}

// ---------------------------------------------------------------------------
// Battery advertisement scan
// ---------------------------------------------------------------------------

void SwitchbotKeypadBridge::apply_pending_keypad_battery_() {
  int value;
  uint8_t mac[6];
  uint8_t family;
  {
    std::lock_guard<std::mutex> lk(this->rx_mutex_);
    if (!this->keypad_battery_advert_pending_) return;
    this->keypad_battery_advert_pending_ = false;
    value = this->keypad_battery_advert_value_;
    std::memcpy(mac, this->keypad_battery_advert_mac_, sizeof(mac));
    family = this->keypad_battery_advert_family_;
  }

  if (this->keypad_info_.valid == 0) {
    std::memcpy(this->keypad_info_.mac, mac, sizeof(this->keypad_info_.mac));
    this->keypad_info_.family = family;
    this->keypad_info_.valid = 1;
    this->save_and_sync_(this->keypad_info_pref_, &this->keypad_info_);
    ESP_LOGI(TAG, "Learned keypad MAC %02X:%02X:%02X:%02X:%02X:%02X from advertisement",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  }

  // Mark this target as satisfied; the window closes once every expected
  // target has reported.
  this->keypad_battery_scan_found_ = true;
  this->publish_battery_if_changed_(this->keypad_battery_level_sensor_, value,
                                    this->last_keypad_battery_, "Keypad");
}

void SwitchbotKeypadBridge::apply_pending_lock_battery_() {
  int value;
  {
    std::lock_guard<std::mutex> lk(this->rx_mutex_);
    if (!this->lock_battery_advert_pending_) return;
    this->lock_battery_advert_pending_ = false;
    value = this->lock_battery_advert_value_;
  }

  this->lock_battery_scan_found_ = true;
  this->publish_battery_if_changed_(this->lock_battery_level_sensor_, value,
                                    this->last_lock_battery_, "Lock");
}

void SwitchbotKeypadBridge::maybe_finish_battery_scan_() {
  if (!this->battery_scan_active_.load(std::memory_order_acquire)) {
    return;
  }
  if (this->battery_scan_wants_keypad_ && !this->keypad_battery_scan_found_) {
    return;
  }
  if (this->battery_scan_wants_lock_ && !this->lock_battery_scan_found_) {
    return;
  }
  this->stop_battery_scan_();
  this->next_battery_scan_at_ = millis() + this->battery_scan_interval_ms_;
}

void SwitchbotKeypadBridge::stop_battery_scan_() {
  if (this->battery_scan_active_.exchange(false, std::memory_order_acq_rel)) {
    NimBLEScan *scan = NimBLEDevice::getScan();
    if (scan->isScanning()) {
      scan->stop();
    }
    scan->clearResults();
  }
  this->battery_scan_wants_keypad_ = false;
  this->battery_scan_wants_lock_ = false;
  this->keypad_battery_scan_found_ = false;
  this->lock_battery_scan_found_ = false;
  this->battery_scan_keypad_known_ = false;
  this->battery_scan_lock_model_ = PhysicalLockModel::UNKNOWN;
}

bool SwitchbotKeypadBridge::background_ble_busy_() const {
  return this->pairing_ui_.is_running() ||
         this->lock_relay_busy_.load(std::memory_order_relaxed) ||
         (this->server_ != nullptr && this->server_->getConnectedCount() > 0);
}

void SwitchbotKeypadBridge::clear_lock_battery_() {
  this->reset_battery_sensor_(this->lock_battery_level_sensor_,
                              this->last_lock_battery_);
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
