// Copyright 2026 The Cypherium Authors
// SPDX-License-Identifier: LGPL-3.0-only

#pragma once

#include "strict_json.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace cph::ccse {

using Bytes = std::vector<std::uint8_t>;
using Digest = std::array<std::uint8_t, 32>;
using MessageId = std::array<std::uint8_t, 16>;

class Failure final : public std::runtime_error {
 public:
  Failure(std::string code, std::string detail);
  [[nodiscard]] const std::string& code() const noexcept { return code_; }

 private:
  std::string code_;
};

Bytes decode_hex(std::string_view input, std::string_view where);
std::string encode_hex(std::span<const std::uint8_t> input);
Digest sha256(std::span<const std::uint8_t> input);

class NfcChecker final {
 public:
  NfcChecker();
  ~NfcChecker();
  NfcChecker(const NfcChecker&) = delete;
  NfcChecker& operator=(const NfcChecker&) = delete;

  [[nodiscard]] bool has_provider() const noexcept;
  [[nodiscard]] bool explicit_provider() const noexcept;
  [[nodiscard]] bool conformance_ready() const noexcept;
  [[nodiscard]] bool exact_icu_72_1() const noexcept;
  [[nodiscard]] bool exact_unicode_15() const noexcept;
  [[nodiscard]] const std::string& icu_version() const noexcept;
  [[nodiscard]] const std::string& unicode_version() const noexcept;
  [[nodiscard]] const std::string& provider_detail() const noexcept;
  [[nodiscard]] bool is_normalized(std::string_view value) const;

 private:
  void* library_ = nullptr;
  const void* normalizer_ = nullptr;
  using IsNormalized = std::int8_t (*)(const void*, const std::uint16_t*,
                                       std::int32_t, std::int32_t*);
  IsNormalized is_normalized_ = nullptr;
  bool explicit_provider_ = false;
  std::string icu_version_;
  std::string unicode_version_;
  std::string provider_detail_;
};

struct Version {
  std::uint32_t major = 0;
  std::uint32_t minor = 0;
  friend bool operator==(const Version&, const Version&) = default;
};

struct OptionalString {
  bool present = false;
  std::string value;
};

struct OptionalMessageId {
  bool present = false;
  MessageId value{};
};

struct Extension {
  std::uint32_t id = 0;
  bool critical = false;
  Bytes value;
};

struct Domain {
  std::string purpose;
  std::string sender_identity;
  std::vector<std::string> audience;
  OptionalString tenant_organization;
  OptionalString provider_organization;
  Digest chain_id{};
  Digest genesis_hash{};
  std::string environment;
  Version protocol_version;
  Version schema_version;
  std::uint32_t signature_algorithm = 0;
  std::string signature_key_id;
  std::int64_t issued_at_unix_nano = 0;
  std::int64_t expires_at_unix_nano = 0;
  std::uint32_t counter_kind = 0;
  std::uint64_t counter = 0;
  std::string replay_domain_id;
};

struct Envelope {
  Version protocol_version;
  Version schema_version;
  MessageId message_id{};
  MessageId correlation_id{};
  OptionalMessageId causation_id;
  std::string sender_identity;
  Digest chain_id{};
  std::string environment;
  std::int64_t issued_at_unix_nano = 0;
  std::int64_t expires_at_unix_nano = 0;
  std::uint32_t counter_kind = 0;
  std::uint64_t counter = 0;
  Digest payload_digest{};
  std::uint32_t signature_algorithm = 0;
  std::string signature_key_id;
  std::vector<Extension> extensions;
};

struct Payload {
  std::string schema_note;
  std::string record_kind;
  OptionalString optional_note;
  std::uint64_t sample_count = 0;
  std::string display_name;
  std::vector<std::string> tags;
  Bytes declared_canonical;
};

struct Record {
  std::uint32_t message_type_id = 0;
  Version schema_version;
  Domain domain;
  Envelope envelope;
  Bytes payload;
  Bytes signature;
};

struct PositiveExpected {
  Bytes canonical_domain;
  Bytes canonical_envelope;
  Bytes preimage;
  Digest digest{};
  Bytes public_key;
  Bytes signature;
};

struct PositiveFixture {
  std::string vector_id;
  std::string status;
  std::uint32_t message_type_id = 0;
  Version schema_version;
  Bytes private_key_seed;
  Domain domain;
  Envelope envelope;
  Payload payload;
  PositiveExpected expected;
};

struct NegativeCase {
  std::string id;
  std::string operation;
  std::string path;
  strict_json::Value value;
  bool has_value = false;
  std::string value_hex;
  bool has_value_hex = false;
  std::int64_t unix_nano = 0;
  bool has_unix_nano = false;
  std::uint32_t extension_id = 0;
  bool has_extension_id = false;
  bool critical = false;
  bool has_critical = false;
  std::int64_t revoked_at_unix_nano = 0;
  bool has_revoked_at = false;
  std::string new_key_id;
  std::string new_private_key_seed_hex;
  std::string expected_error;
  std::string expected_result;
};

struct NegativeFixture {
  std::string vector_set_id;
  std::string base_vector_id;
  std::string status;
  std::vector<NegativeCase> cases;
};

PositiveFixture parse_positive_fixture(const strict_json::Value& root);
NegativeFixture parse_negative_fixture(const strict_json::Value& root);

Bytes canonical_payload(const Payload& payload, const NfcChecker& nfc);
Bytes canonical_domain(const Domain& domain, const NfcChecker& nfc);
Bytes canonical_envelope(const Envelope& envelope, const NfcChecker& nfc);
Bytes preimage(const Record& record, const NfcChecker& nfc);
Bytes ed25519_public_from_seed(std::span<const std::uint8_t> seed);
Bytes ed25519_sign_digest(std::span<const std::uint8_t> seed,
                          std::span<const std::uint8_t> digest);
bool ed25519_verify_digest(std::span<const std::uint8_t> public_key,
                           std::span<const std::uint8_t> digest,
                           std::span<const std::uint8_t> signature);

Record make_base_record(const PositiveFixture& fixture, const NfcChecker& nfc);
void resign(Record& record, std::span<const std::uint8_t> seed,
            const NfcChecker& nfc);
void validate_record(const Record& record, const NfcChecker& nfc);

}  // namespace cph::ccse
