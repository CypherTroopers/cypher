// Copyright 2026 The Cypherium Authors
// SPDX-License-Identifier: LGPL-3.0-only

#include "ccse.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>

namespace {

using cph::ccse::Bytes;
using cph::ccse::Failure;
using cph::ccse::NegativeCase;
using cph::ccse::NfcChecker;
using cph::ccse::PositiveFixture;
using cph::ccse::Record;

[[noreturn]] void test_failure(const std::string& detail) {
  throw std::runtime_error("conformance failure: " + detail);
}

void require(bool condition, const std::string& detail) {
  if (!condition) test_failure(detail);
}

template <typename Function>
void require_json_error(Function&& function, const std::string& detail) {
  try {
    std::forward<Function>(function)();
  } catch (const strict_json::Error&) {
    return;
  }
  test_failure(detail);
}

void test_strict_json_contract() {
  require_json_error(
      [] { (void)strict_json::parse(R"({"a":1,"a":2})"); },
      "JSON duplicate key was accepted");
  require_json_error([] { (void)strict_json::parse("{} trailing"); },
                     "JSON trailing data was accepted");
  require_json_error(
      [] {
        const auto value = strict_json::parse(R"({"known":1,"unknown":2})");
        strict_json::expect_keys(value, "self-test", {"known"});
      },
      "JSON unknown field was accepted");
  require_json_error(
      [] { (void)strict_json::parse(R"({"n":01})"); },
      "JSON non-canonical leading-zero number was accepted");
}

std::vector<std::string> string_array_value(const NegativeCase& item,
                                            std::string_view where) {
  if (!item.has_value) test_failure(std::string(where) + ": missing value");
  const auto& values = item.value.as_array(where);
  std::vector<std::string> output;
  output.reserve(values.size());
  for (std::size_t i = 0; i < values.size(); ++i) {
    output.push_back(values[i].as_string(std::string(where) + "[" +
                                         std::to_string(i) + "]"));
  }
  return output;
}

bool equal_string_set(std::vector<std::string> left,
                      std::vector<std::string> right) {
  if (left.size() != right.size()) return false;
  std::sort(left.begin(), left.end());
  std::sort(right.begin(), right.end());
  for (std::size_t i = 0; i < left.size(); ++i) {
    if (left[i] != right[i] || (i != 0 && left[i] == left[i - 1])) return false;
  }
  return true;
}

void test_audience_set_contract() {
  require(equal_string_set({"audit", "evidence"}, {"evidence", "audit"}),
          "audience canonical set permutation was not equal");
  require(!equal_string_set({"audit", "evidence"}, {"audit", "other"}),
          "audience overlap was incorrectly accepted as exact equality");
  require(!equal_string_set({"audit", "evidence"}, {"audit"}),
          "audience subset was incorrectly accepted as exact equality");
  require(!equal_string_set({"audit", "audit"}, {"audit", "audit"}),
          "duplicate audience set was accepted");
}

void verify_signature(const Record& record, const Bytes& public_key,
                      const NfcChecker& nfc) {
  cph::ccse::validate_record(record, nfc);
  if (record.domain.signature_algorithm != 1 ||
      record.envelope.signature_algorithm != 1) {
    throw Failure("UNSUPPORTED_ALGORITHM", "only Ed25519 is enabled in this consumer");
  }
  const auto digest = cph::ccse::sha256(cph::ccse::preimage(record, nfc));
  if (!cph::ccse::ed25519_verify_digest(public_key, digest, record.signature)) {
    throw Failure("INVALID_SIGNATURE", "OpenSSL rejected Ed25519 signature");
  }
}

void verify_extension_registry(const Record& record) {
  // The conformance-only message type 100 registers no signed extensions.
  // Unknown non-critical fields are not ignored inside the signing projection.
  for (const auto& extension : record.envelope.extensions) {
    throw Failure(extension.critical ? "UNKNOWN_CRITICAL_EXTENSION"
                                     : "UNKNOWN_EXTENSION",
                  "extension ID " + std::to_string(extension.id) +
                      " is absent from the exact schema registry");
  }
}

struct ReplayScope {
  std::uint32_t counter_kind = 0;
  std::string replay_domain_id;
  std::string sender_identity;
  std::string environment;
  cph::ccse::Digest chain_id{};
  cph::ccse::Digest genesis_hash{};

  friend bool operator<(const ReplayScope& left, const ReplayScope& right) {
    return std::tie(left.counter_kind, left.replay_domain_id, left.sender_identity,
                    left.environment, left.chain_id, left.genesis_hash) <
           std::tie(right.counter_kind, right.replay_domain_id,
                    right.sender_identity, right.environment, right.chain_id,
                    right.genesis_hash);
  }
};

struct ReplayMessage {
  ReplayScope scope;
  cph::ccse::MessageId message_id{};

  friend bool operator<(const ReplayMessage& left, const ReplayMessage& right) {
    return std::tie(left.scope, left.message_id) <
           std::tie(right.scope, right.message_id);
  }
};

ReplayScope replay_scope(const Record& record) {
  return ReplayScope{
      .counter_kind = record.domain.counter_kind,
      .replay_domain_id = record.domain.replay_domain_id,
      .sender_identity = record.domain.sender_identity,
      .environment = record.domain.environment,
      .chain_id = record.domain.chain_id,
      .genesis_hash = record.domain.genesis_hash,
  };
}

class ReplayHarness final {
 public:
  std::string apply(const Record& record, const Bytes& public_key,
                    const NfcChecker& nfc, bool handler_succeeds) {
    verify_signature(record, public_key, nfc);
    verify_extension_registry(record);
    const auto authorization = cph::ccse::sha256(cph::ccse::preimage(record, nfc));
    const std::string authorization_hex = cph::ccse::encode_hex(authorization);
    const ReplayScope scope = replay_scope(record);
    const ReplayMessage message{.scope = scope,
                                .message_id = record.envelope.message_id};
    if (const auto found = messages_.find(message); found != messages_.end()) {
      if (found->second != authorization_hex) {
        throw Failure("MESSAGE_ID_CONFLICT",
                      "message ID reused with different authorization bytes");
      }
      throw Failure("DUPLICATE_MESSAGE_USE_IDEMPOTENT_RESULT",
                    "return the previously committed idempotent result");
    }
    if (const auto found = counters_.find(scope);
        found != counters_.end() && record.domain.counter <= found->second) {
      throw Failure("REPLAY_SEQUENCE", "counter is not strictly increasing");
    }

    // Reservation and handler effect are one rollback unit in this in-memory
    // conformance model. A handler failure leaves no replay tombstone.
    messages_.emplace(message, authorization_hex);
    const auto old_counter = counters_.find(scope);
    const std::optional<std::uint64_t> previous =
        old_counter == counters_.end() ? std::nullopt
                                       : std::optional<std::uint64_t>(old_counter->second);
    counters_[scope] = record.domain.counter;
    if (!handler_succeeds) {
      messages_.erase(message);
      if (previous.has_value()) {
        counters_[scope] = *previous;
      } else {
        counters_.erase(scope);
      }
      throw Failure("HANDLER_ROLLBACK", "simulated business handler failure");
    }
    return "APPLIED";
  }

 private:
  std::map<ReplayMessage, std::string> messages_;
  std::map<ReplayScope, std::uint64_t> counters_;
};

void test_replay_key_contract(const PositiveFixture& fixture,
                              const NfcChecker& nfc) {
  Record left = cph::ccse::make_base_record(fixture, nfc);
  // These two scopes collide under delimiter concatenation:
  // sender="a|b", replay="c" versus sender="a", replay="b|c".
  left.domain.sender_identity = "a|b";
  left.envelope.sender_identity = left.domain.sender_identity;
  left.domain.replay_domain_id = "c";
  cph::ccse::resign(left, fixture.private_key_seed, nfc);

  Record right = cph::ccse::make_base_record(fixture, nfc);
  right.domain.sender_identity = "a";
  right.envelope.sender_identity = right.domain.sender_identity;
  right.domain.replay_domain_id = "b|c";
  cph::ccse::resign(right, fixture.private_key_seed, nfc);

  ReplayHarness replay;
  require(replay.apply(left, fixture.expected.public_key, nfc, true) == "APPLIED",
          "typed replay key first scope was not applied");
  require(replay.apply(right, fixture.expected.public_key, nfc, true) == "APPLIED",
          "typed replay key collided or message ID was treated as global");
}

std::string execute_case(const NegativeCase& item, const PositiveFixture& fixture,
                         const NfcChecker& nfc) {
  Record base = cph::ccse::make_base_record(fixture, nfc);

  if (item.operation == "compare_digest") {
    require(item.path == "domain.tenant_organization.present" && item.has_value,
            item.id + ": unsupported compare_digest mutation");
    Record changed = base;
    changed.domain.tenant_organization.present =
        item.value.as_bool(item.id + ".value");
    const auto original = cph::ccse::sha256(cph::ccse::preimage(base, nfc));
    const auto mutated = cph::ccse::sha256(cph::ccse::preimage(changed, nfc));
    return original == mutated ? "SAME_DIGEST" : "DIFFERENT_DIGEST";
  }

  if (item.operation == "encode" || item.operation == "encode_equivalent") {
    auto payload = fixture.payload;
    if (item.path == "payload_projection.display_name") {
      require(item.has_value, item.id + ": missing string mutation");
      payload.display_name = item.value.as_string(item.id + ".value");
    } else if (item.path == "payload_projection.tags_set_unsorted") {
      payload.tags = string_array_value(item, item.id + ".value");
    } else {
      test_failure(item.id + ": unsupported payload mutation path");
    }
    const Bytes encoded = cph::ccse::canonical_payload(payload, nfc);
    if (item.operation == "encode_equivalent") {
      return encoded == base.payload ? "SAME_CANONICAL_BYTES"
                                     : "DIFFERENT_CANONICAL_BYTES";
    }
    return "ENCODED";
  }

  if (item.operation == "verify_with") {
    verify_signature(base, fixture.expected.public_key, nfc);
    verify_extension_registry(base);
    if (item.path == "expectations.audience") {
      const auto expected = string_array_value(item, item.id + ".value");
      if (!equal_string_set(base.domain.audience, expected)) {
        throw Failure("WRONG_AUDIENCE", "exact canonical audience set mismatch");
      }
    } else if (item.path == "expectations.environment") {
      require(item.has_value, item.id + ": missing environment value");
      if (base.domain.environment != item.value.as_string(item.id + ".value")) {
        throw Failure("WRONG_ENVIRONMENT", "environment expectation mismatch");
      }
    } else if (item.path == "expectations.chain_id") {
      require(item.has_value_hex, item.id + ": missing chain ID");
      if (base.domain.chain_id !=
          [&] {
            const auto decoded = cph::ccse::decode_hex(item.value_hex, item.id + ".value_hex");
            require(decoded.size() == 32, item.id + ": chain ID width");
            std::array<std::uint8_t, 32> value{};
            std::copy(decoded.begin(), decoded.end(), value.begin());
            return value;
          }()) {
        throw Failure("WRONG_CHAIN", "chain ID expectation mismatch");
      }
    } else if (item.path == "expectations.genesis_hash") {
      require(item.has_value_hex, item.id + ": missing genesis hash");
      const auto decoded = cph::ccse::decode_hex(item.value_hex, item.id + ".value_hex");
      require(decoded.size() == 32, item.id + ": genesis hash width");
      std::array<std::uint8_t, 32> value{};
      std::copy(decoded.begin(), decoded.end(), value.begin());
      if (base.domain.genesis_hash != value) {
        throw Failure("WRONG_GENESIS", "genesis hash expectation mismatch");
      }
    } else {
      test_failure(item.id + ": unsupported verification expectation");
    }
    return "VERIFIED";
  }

  if (item.operation == "verify_at") {
    require(item.has_unix_nano, item.id + ": missing verification time");
    verify_signature(base, fixture.expected.public_key, nfc);
    if (item.unix_nano >= base.domain.expires_at_unix_nano) {
      throw Failure("EXPIRED", "record validity window has ended");
    }
    return "VERIFIED";
  }

  if (item.operation == "resign_with_extension") {
    require(item.has_extension_id && item.has_critical,
            item.id + ": incomplete extension mutation");
    base.envelope.extensions.push_back(cph::ccse::Extension{
        .id = item.extension_id, .critical = item.critical, .value = {}});
    cph::ccse::resign(base, fixture.private_key_seed, nfc);
    verify_signature(base, fixture.expected.public_key, nfc);
    verify_extension_registry(base);
    return "VERIFIED";
  }

  if (item.operation == "revoke_then_verify") {
    require(item.has_revoked_at, item.id + ": missing revocation time");
    verify_signature(base, fixture.expected.public_key, nfc);
    if (base.domain.expires_at_unix_nano >= item.revoked_at_unix_nano) {
      throw Failure("KEY_REVOKED", "operation validity extends into revocation window");
    }
    return "VERIFIED";
  }

  if (item.operation == "verify_complete_then_verify_again") {
    ReplayHarness replay;
    require(replay.apply(base, fixture.expected.public_key, nfc, true) == "APPLIED",
            item.id + ": first application failed");
    return replay.apply(base, fixture.expected.public_key, nfc, true);
  }

  if (item.operation == "handler_error_then_retry") {
    ReplayHarness replay;
    try {
      (void)replay.apply(base, fixture.expected.public_key, nfc, false);
      test_failure(item.id + ": simulated handler error was not raised");
    } catch (const Failure& error) {
      require(error.code() == "HANDLER_ROLLBACK",
              item.id + ": wrong rollback failure code");
    }
    require(replay.apply(base, fixture.expected.public_key, nfc, true) == "APPLIED",
            item.id + ": retry did not apply");
    return "RETRY_APPLIED_AFTER_ROLLBACK";
  }

  if (item.operation == "new_message_same_sequence") {
    ReplayHarness replay;
    require(replay.apply(base, fixture.expected.public_key, nfc, true) == "APPLIED",
            item.id + ": base application failed");
    Record changed = base;
    changed.envelope.message_id.back() ^= 0x80;
    cph::ccse::resign(changed, fixture.private_key_seed, nfc);
    return replay.apply(changed, fixture.expected.public_key, nfc, true);
  }

  if (item.operation == "rotate_key_new_message_same_sequence") {
    ReplayHarness replay;
    require(replay.apply(base, fixture.expected.public_key, nfc, true) == "APPLIED",
            item.id + ": base application failed");
    require(!item.new_key_id.empty() && !item.new_private_key_seed_hex.empty(),
            item.id + ": missing rotated key material");
    const Bytes new_seed = cph::ccse::decode_hex(
        item.new_private_key_seed_hex, item.id + ".new_private_key_seed_hex");
    require(new_seed.size() == 32, item.id + ": rotated seed must be 32 bytes");
    Record changed = base;
    changed.domain.signature_key_id = item.new_key_id;
    changed.envelope.signature_key_id = item.new_key_id;
    changed.envelope.message_id.front() ^= 0x80;
    cph::ccse::resign(changed, new_seed, nfc);
    const Bytes new_public_key = cph::ccse::ed25519_public_from_seed(new_seed);
    return replay.apply(changed, new_public_key, nfc, true);
  }

  if (item.operation == "same_message_id_different_payload") {
    ReplayHarness replay;
    require(replay.apply(base, fixture.expected.public_key, nfc, true) == "APPLIED",
            item.id + ": base application failed");
    auto changed_payload = fixture.payload;
    ++changed_payload.sample_count;
    Record changed = base;
    changed.payload = cph::ccse::canonical_payload(changed_payload, nfc);
    cph::ccse::resign(changed, fixture.private_key_seed, nfc);
    return replay.apply(changed, fixture.expected.public_key, nfc, true);
  }

  if (item.operation == "mutate_domain_and_envelope") {
    require(item.path == "signature_algorithm_id" && item.has_value,
            item.id + ": unsupported domain/envelope mutation");
    const auto algorithm = item.value.as_u64(item.id + ".value");
    require(algorithm <= std::numeric_limits<std::uint32_t>::max(),
            item.id + ": algorithm width");
    base.domain.signature_algorithm = static_cast<std::uint32_t>(algorithm);
    base.envelope.signature_algorithm = static_cast<std::uint32_t>(algorithm);
    cph::ccse::validate_record(base, nfc);
    return "VERIFIED";
  }

  test_failure(item.id + ": unknown negative-vector operation " + item.operation);
}

void run_negative_case(const NegativeCase& item, const PositiveFixture& fixture,
                       const NfcChecker& nfc) {
  try {
    const std::string result = execute_case(item, fixture, nfc);
    if (!item.expected_error.empty()) {
      test_failure(item.id + ": expected error " + item.expected_error +
                   ", received result " + result);
    }
    require(result == item.expected_result,
            item.id + ": expected result " + item.expected_result +
                ", received " + result);
  } catch (const Failure& error) {
    if (item.expected_error.empty()) throw;
    require(error.code() == item.expected_error,
            item.id + ": expected error " + item.expected_error +
                ", received " + error.code());
  }
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc != 3) {
      std::cerr << "usage: " << argv[0]
                << " <ccse_v1_ed25519_positive.json> <ccse_v1_negative.json>\n";
      return 64;
    }

    test_strict_json_contract();
    test_audience_set_contract();
    const auto positive = cph::ccse::parse_positive_fixture(
        strict_json::parse_file(argv[1]));
    const auto negative = cph::ccse::parse_negative_fixture(
        strict_json::parse_file(argv[2]));
    require(negative.base_vector_id == positive.vector_id,
            "negative base_vector_id does not match positive vector_id");
    require((positive.status == "candidate" || positive.status == "frozen") &&
                (negative.status == "candidate" || negative.status == "frozen"),
            "unsupported fixture lifecycle status");

    NfcChecker nfc;
    if (!nfc.has_provider()) {
      std::cerr << "BLOCKER: " << nfc.provider_detail() << '\n';
      return 2;
    }
    const bool dependency_blocker = !nfc.conformance_ready();

    const Bytes payload = cph::ccse::canonical_payload(positive.payload, nfc);
    require(payload == positive.payload.declared_canonical,
            "payload input does not produce payload_projection.canonical_hex");
    const Record record = cph::ccse::make_base_record(positive, nfc);
    require(cph::ccse::canonical_domain(record.domain, nfc) ==
                positive.expected.canonical_domain,
            "domain input does not produce expected canonical bytes");
    require(cph::ccse::canonical_envelope(record.envelope, nfc) ==
                positive.expected.canonical_envelope,
            "envelope input does not produce expected canonical bytes");
    const Bytes canonical_preimage = cph::ccse::preimage(record, nfc);
    require(canonical_preimage == positive.expected.preimage,
            "input projections do not produce expected preimage");
    const auto digest = cph::ccse::sha256(canonical_preimage);
    require(digest == positive.expected.digest,
            "OpenSSL SHA-256 does not produce expected digest");
    require(cph::ccse::ed25519_public_from_seed(positive.private_key_seed) ==
                positive.expected.public_key,
            "OpenSSL Ed25519 seed derivation does not produce expected public key");
    require(cph::ccse::ed25519_sign_digest(positive.private_key_seed, digest) ==
                positive.expected.signature,
            "OpenSSL Ed25519 signing does not produce expected signature");
    require(cph::ccse::ed25519_verify_digest(positive.expected.public_key, digest,
                                             positive.expected.signature),
            "OpenSSL Ed25519 verification rejected positive vector");
    test_replay_key_contract(positive, nfc);

    std::set<std::string> operations;
    std::set<std::string> case_ids;
    for (const auto& item : negative.cases) {
      run_negative_case(item, positive, nfc);
      operations.insert(item.operation);
      case_ids.insert(item.id);
      std::cout << (dependency_blocker ? "[PROVISIONAL] " : "[PASS] ") << item.id
                << '\n';
    }
    const std::set<std::string> required_operations{
        "compare_digest", "encode", "encode_equivalent", "verify_with",
        "verify_at", "resign_with_extension", "revoke_then_verify",
        "verify_complete_then_verify_again", "handler_error_then_retry",
        "new_message_same_sequence", "rotate_key_new_message_same_sequence",
        "same_message_id_different_payload",
        "mutate_domain_and_envelope"};
    for (const auto& operation : required_operations) {
      require(operations.contains(operation),
              "fixture omits required negative operation " + operation);
    }
    const std::set<std::string> required_case_ids{
        "present-empty-is-not-absent", "non-nfc-string", "set-permutation",
        "set-duplicate", "wrong-audience", "wrong-environment", "wrong-chain",
        "wrong-genesis", "expired", "unknown-critical-extension",
        "unknown-noncritical-extension", "revoked-key", "exact-message-duplicate",
        "handler-rollback-safe-retry", "sequence-replay",
        "key-rotation-does-not-reset-replay", "message-id-conflict",
        "algorithm-downgrade"};
    for (const auto& id : required_case_ids) {
      require(case_ids.contains(id), "fixture omits required negative case " + id);
    }

    std::cout << "JSON provider: internal bounded strict-json revision 1 "
                 "(RFC 8259 grammar); duplicate keys, unknown fields, trailing "
                 "data and non-canonical integer forms rejected\n";
    std::cout << "Audience/replay key self-tests: exact-set and typed-scope checks passed\n";
    std::cout << "Compiler: " << __VERSION__ << " (ISO C++20)\n";
    std::cout << "Crypto headers: " << OPENSSL_VERSION_TEXT << '\n';
    std::cout << "Crypto provider: " << OpenSSL_version(OPENSSL_VERSION) << '\n';
    std::cout << "Unicode provider: " << nfc.provider_detail() << '\n';
    std::cout << "Vectors executed: 1 positive, " << negative.cases.size()
              << " negative\n";
    if (dependency_blocker) {
      std::cerr
          << "BLOCKER: reproducible CCSE-v1 conformance requires an explicitly "
             "selected ICU 72.1 provider with Unicode 15.0.0, but this executable "
             "loaded "
          << nfc.provider_detail()
          << ". All vector computations above were executed, but they are "
             "PROVISIONAL and this consumer MUST NOT claim conformance. Use the "
             "pinned provisioning and reproducible-test scripts, or explicitly "
             "set CPH_CCSE_ICU_LIBRARY and CPH_CCSE_ICU_ABI.\n";
      return 2;
    }
    std::cout << "PASS: independent C++20 CCSE-v1 conformance consumer\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "FAIL: " << error.what() << '\n';
    return 1;
  }
}
