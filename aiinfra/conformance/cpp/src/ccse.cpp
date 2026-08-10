// Copyright 2026 The Cypherium Authors
// SPDX-License-Identifier: LGPL-3.0-only

#include "ccse.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <limits>
#include <memory>
#include <sstream>
#include <utility>

namespace cph::ccse {
namespace {

constexpr char kPreambleBytes[] = "CPH-AIIE-CCSE-V1\0";
constexpr std::string_view kPreamble{kPreambleBytes, sizeof(kPreambleBytes) - 1};
constexpr std::size_t kMaxProjection = 8U << 20;
constexpr std::size_t kMaxAudience = 64;
constexpr std::size_t kMaxExtensions = 64;

[[noreturn]] void fail(std::string code, std::string detail) {
  throw Failure(std::move(code), std::move(detail));
}

std::string openssl_error() {
  const unsigned long code = ERR_get_error();
  if (code == 0) return "OpenSSL returned failure without an error record";
  std::array<char, 256> buffer{};
  ERR_error_string_n(code, buffer.data(), buffer.size());
  return buffer.data();
}

template <std::size_t Size>
std::array<std::uint8_t, Size> decode_fixed(std::string_view input,
                                            std::string_view where) {
  const Bytes decoded = decode_hex(input, where);
  if (decoded.size() != Size) {
    throw strict_json::Error(std::string(where) + ": expected " +
                             std::to_string(Size) + " decoded bytes");
  }
  std::array<std::uint8_t, Size> output{};
  std::copy(decoded.begin(), decoded.end(), output.begin());
  return output;
}

std::uint32_t checked_u32(const strict_json::Value& value,
                          std::string_view where) {
  const auto input = value.as_u64(where);
  if (input > std::numeric_limits<std::uint32_t>::max()) {
    throw strict_json::Error(std::string(where) + ": integer exceeds uint32");
  }
  return static_cast<std::uint32_t>(input);
}

Version parse_version(const strict_json::Value& value, std::string_view where) {
  strict_json::expect_keys(value, where, {"major", "minor"});
  return Version{
      .major = checked_u32(strict_json::member(value, "major", where),
                           std::string(where) + ".major"),
      .minor = checked_u32(strict_json::member(value, "minor", where),
                           std::string(where) + ".minor"),
  };
}

OptionalString parse_optional_string(const strict_json::Value& value,
                                     std::string_view where) {
  strict_json::expect_keys(value, where, {"present", "value"});
  return OptionalString{
      .present = strict_json::member(value, "present", where).as_bool(
          std::string(where) + ".present"),
      .value = strict_json::member(value, "value", where).as_string(
          std::string(where) + ".value"),
  };
}

std::vector<std::string> parse_string_array(const strict_json::Value& value,
                                            std::string_view where) {
  const auto& values = value.as_array(where);
  std::vector<std::string> output;
  output.reserve(values.size());
  for (std::size_t i = 0; i < values.size(); ++i) {
    output.push_back(values[i].as_string(std::string(where) + "[" +
                                         std::to_string(i) + "]"));
  }
  return output;
}

bool all_zero(std::span<const std::uint8_t> input) {
  return std::all_of(input.begin(), input.end(),
                     [](std::uint8_t value) { return value == 0; });
}

class Encoder final {
 public:
  explicit Encoder(const NfcChecker& nfc) : nfc_(nfc) {}

  void boolean(bool value) {
    raw(std::array<std::uint8_t, 1>{static_cast<std::uint8_t>(value ? 1 : 0)});
  }

  void u32(std::uint32_t value) {
    raw(std::array<std::uint8_t, 4>{
        static_cast<std::uint8_t>(value >> 24),
        static_cast<std::uint8_t>(value >> 16),
        static_cast<std::uint8_t>(value >> 8),
        static_cast<std::uint8_t>(value),
    });
  }

  void u64(std::uint64_t value) {
    std::array<std::uint8_t, 8> output{};
    for (int i = 7; i >= 0; --i) {
      output[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(value);
      value >>= 8;
    }
    raw(output);
  }

  void i64(std::int64_t value) { u64(static_cast<std::uint64_t>(value)); }

  void bytes(std::span<const std::uint8_t> value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
      fail("PROJECTION_TOO_LARGE", "byte string exceeds uint32 length");
    }
    u32(static_cast<std::uint32_t>(value.size()));
    raw(value);
  }

  void string(std::string_view value) {
    if (!nfc_.has_provider()) {
      fail("UNICODE_BLOCKER", "no complete Unicode NFC provider is available");
    }
    if (!nfc_.is_normalized(value)) {
      fail("NON_NFC_STRING", "string is not NFC normalized");
    }
    bytes(std::span(reinterpret_cast<const std::uint8_t*>(value.data()), value.size()));
  }

  template <std::size_t Size>
  void fixed(const std::array<std::uint8_t, Size>& value) {
    bytes(value);
  }

  void optional_string(const OptionalString& value) {
    if (!value.present && !value.value.empty()) {
      fail("NON_CANONICAL_ABSENT", "absent optional string retains a value");
    }
    boolean(value.present);
    if (value.present) string(value.value);
  }

  void encoded_list(const std::vector<Bytes>& values) {
    if (values.size() > std::numeric_limits<std::uint32_t>::max()) {
      fail("TOO_MANY_ELEMENTS", "list exceeds uint32 element count");
    }
    u32(static_cast<std::uint32_t>(values.size()));
    for (const auto& value : values) bytes(value);
  }

  void string_set(const std::vector<std::string>& values) {
    std::vector<Bytes> encoded;
    encoded.reserve(values.size());
    for (const auto& value : values) {
      Encoder item(nfc_);
      item.string(value);
      encoded.push_back(item.finish());
    }
    std::sort(encoded.begin(), encoded.end());
    if (std::adjacent_find(encoded.begin(), encoded.end()) != encoded.end()) {
      fail("DUPLICATE_SET_VALUE", "duplicate canonical set member");
    }
    encoded_list(encoded);
  }

  Bytes finish() && { return std::move(output_); }
  Bytes finish() const& { return output_; }

 private:
  void raw(std::span<const std::uint8_t> value) {
    if (value.size() > kMaxProjection || output_.size() > kMaxProjection - value.size()) {
      fail("PROJECTION_TOO_LARGE", "canonical projection exceeds bound");
    }
    output_.insert(output_.end(), value.begin(), value.end());
  }

  const NfcChecker& nfc_;
  Bytes output_;
};

void encode_version(Encoder& encoder, const Version& value) {
  encoder.u32(value.major);
  encoder.u32(value.minor);
}

std::vector<std::uint16_t> utf8_to_utf16(std::string_view input) {
  std::vector<std::uint16_t> output;
  output.reserve(input.size());
  std::size_t i = 0;
  while (i < input.size()) {
    const auto first = static_cast<unsigned char>(input[i++]);
    std::uint32_t point = 0;
    std::size_t continuation = 0;
    std::uint32_t minimum = 0;
    if (first <= 0x7f) {
      point = first;
    } else if (first >= 0xc2 && first <= 0xdf) {
      point = first & 0x1f;
      continuation = 1;
      minimum = 0x80;
    } else if (first >= 0xe0 && first <= 0xef) {
      point = first & 0x0f;
      continuation = 2;
      minimum = 0x800;
    } else if (first >= 0xf0 && first <= 0xf4) {
      point = first & 0x07;
      continuation = 3;
      minimum = 0x10000;
    } else {
      fail("INVALID_UTF8", "invalid UTF-8 leading byte");
    }
    if (input.size() - i < continuation) {
      fail("INVALID_UTF8", "truncated UTF-8 sequence");
    }
    for (std::size_t part = 0; part < continuation; ++part) {
      const auto next = static_cast<unsigned char>(input[i++]);
      if ((next & 0xc0) != 0x80) {
        fail("INVALID_UTF8", "invalid UTF-8 continuation byte");
      }
      point = (point << 6) | (next & 0x3f);
    }
    if ((continuation != 0 && point < minimum) || point > 0x10ffff ||
        (point >= 0xd800 && point <= 0xdfff)) {
      fail("INVALID_UTF8", "invalid UTF-8 scalar value");
    }
    if (point <= 0xffff) {
      output.push_back(static_cast<std::uint16_t>(point));
    } else {
      point -= 0x10000;
      output.push_back(static_cast<std::uint16_t>(0xd800 | (point >> 10)));
      output.push_back(static_cast<std::uint16_t>(0xdc00 | (point & 0x3ff)));
    }
  }
  if (output.size() > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
    fail("PROJECTION_TOO_LARGE", "Unicode string exceeds ICU length range");
  }
  return output;
}

template <typename Function>
Function load_icu_symbol(void* library, const std::string& base,
                         const std::string& suffix,
                         bool allow_unsuffixed) {
  if (void* symbol = dlsym(library, (base + suffix).c_str()); symbol != nullptr) {
    return reinterpret_cast<Function>(symbol);
  }
  if (allow_unsuffixed) {
    if (void* symbol = dlsym(library, base.c_str()); symbol != nullptr) {
      return reinterpret_cast<Function>(symbol);
    }
  }
  return nullptr;
}

std::string render_icu_version(const std::array<std::uint8_t, 4>& version) {
  std::ostringstream rendered;
  rendered << static_cast<unsigned>(version[0]) << '.'
           << static_cast<unsigned>(version[1]) << '.'
           << static_cast<unsigned>(version[2]);
  return rendered.str();
}

}  // namespace

Failure::Failure(std::string code, std::string detail)
    : std::runtime_error(code + ": " + detail), code_(std::move(code)) {}

Bytes decode_hex(std::string_view input, std::string_view where) {
  if ((input.size() & 1U) != 0) {
    throw strict_json::Error(std::string(where) + ": odd-length hex string");
  }
  auto digit = [where](char value) -> std::uint8_t {
    if (value >= '0' && value <= '9') return static_cast<std::uint8_t>(value - '0');
    if (value >= 'a' && value <= 'f') return static_cast<std::uint8_t>(value - 'a' + 10);
    if (value >= 'A' && value <= 'F') return static_cast<std::uint8_t>(value - 'A' + 10);
    throw strict_json::Error(std::string(where) + ": invalid hex digit");
  };
  Bytes output(input.size() / 2);
  for (std::size_t i = 0; i < output.size(); ++i) {
    output[i] = static_cast<std::uint8_t>((digit(input[2 * i]) << 4) |
                                          digit(input[2 * i + 1]));
  }
  return output;
}

std::string encode_hex(std::span<const std::uint8_t> input) {
  constexpr char alphabet[] = "0123456789abcdef";
  std::string output(input.size() * 2, '0');
  for (std::size_t i = 0; i < input.size(); ++i) {
    output[2 * i] = alphabet[input[i] >> 4];
    output[2 * i + 1] = alphabet[input[i] & 0x0f];
  }
  return output;
}

Digest sha256(std::span<const std::uint8_t> input) {
  Digest output{};
  unsigned int written = 0;
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(),
                                                                 EVP_MD_CTX_free);
  if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(context.get(), input.data(), input.size()) != 1 ||
      EVP_DigestFinal_ex(context.get(), output.data(), &written) != 1 ||
      written != output.size()) {
    fail("CRYPTO_FAILURE", openssl_error());
  }
  return output;
}

NfcChecker::NfcChecker() {
  using GetNormalizer = const void* (*)(std::int32_t*);
  using GetVersion = void (*)(std::uint8_t*);

  const char* explicit_library = std::getenv("CPH_CCSE_ICU_LIBRARY");
  const char* explicit_abi = std::getenv("CPH_CCSE_ICU_ABI");
  const char* allow_ambient = std::getenv("CPH_CCSE_ALLOW_AMBIENT_ICU");
  const bool has_explicit_library =
      explicit_library != nullptr && explicit_library[0] != '\0';
  const bool has_explicit_abi = explicit_abi != nullptr && explicit_abi[0] != '\0';
  const bool ambient_enabled =
      allow_ambient != nullptr && std::string_view(allow_ambient) == "1";

  if ((allow_ambient != nullptr && allow_ambient[0] != '\0' && !ambient_enabled) ||
      (ambient_enabled && (has_explicit_library || has_explicit_abi))) {
    provider_detail_ =
        "invalid ICU selection: CPH_CCSE_ALLOW_AMBIENT_ICU must be exactly 1 "
        "and cannot be combined with an explicit provider";
    return;
  }
  if (has_explicit_library != has_explicit_abi) {
    provider_detail_ =
        "invalid ICU selection: CPH_CCSE_ICU_LIBRARY and CPH_CCSE_ICU_ABI "
        "must be set together";
    return;
  }

  auto load_candidate = [&](const std::string& library_name, int abi,
                            bool is_explicit) -> bool {
    void* candidate = dlopen(library_name.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (candidate == nullptr) {
      if (is_explicit) {
        const char* detail = dlerror();
        provider_detail_ = "explicit ICU load failed for " + library_name;
        if (detail != nullptr) provider_detail_ += ": " + std::string(detail);
      }
      return false;
    }
    const std::string suffix = "_" + std::to_string(abi);
    const auto get_normalizer =
        load_icu_symbol<GetNormalizer>(candidate, "unorm2_getNFCInstance", suffix,
                                       !is_explicit);
    const auto get_unicode_version =
        load_icu_symbol<GetVersion>(candidate, "u_getUnicodeVersion", suffix,
                                    !is_explicit);
    const auto get_icu_version =
        load_icu_symbol<GetVersion>(candidate, "u_getVersion", suffix,
                                    !is_explicit);
    const auto check =
        load_icu_symbol<IsNormalized>(candidate, "unorm2_isNormalized", suffix,
                                      !is_explicit);
    if (get_normalizer == nullptr || get_unicode_version == nullptr ||
        get_icu_version == nullptr || check == nullptr) {
      dlclose(candidate);
      if (is_explicit) {
        provider_detail_ = "explicit ICU provider " + library_name +
                           " does not export the required ABI-suffixed symbols";
      }
      return false;
    }
    std::int32_t error = 0;
    const void* normalizer = get_normalizer(&error);
    if (error > 0 || normalizer == nullptr) {
      dlclose(candidate);
      if (is_explicit) {
        provider_detail_ =
            "explicit ICU provider could not initialize the NFC normalizer";
      }
      return false;
    }
    std::array<std::uint8_t, 4> unicode_version{};
    std::array<std::uint8_t, 4> icu_version{};
    get_unicode_version(unicode_version.data());
    get_icu_version(icu_version.data());
    if (library_ != nullptr) dlclose(library_);
    library_ = candidate;
    normalizer_ = normalizer;
    is_normalized_ = check;
    explicit_provider_ = is_explicit;
    unicode_version_ = render_icu_version(unicode_version);
    icu_version_ = render_icu_version(icu_version);
    provider_detail_ = (is_explicit ? "explicit " : "ambient development ") +
                       library_name + " (ICU " + icu_version_ + ", Unicode " +
                       unicode_version_ + ')';
    return true;
  };

  if (has_explicit_library) {
    const std::filesystem::path library_path(explicit_library);
    if (!library_path.is_absolute()) {
      provider_detail_ = "CPH_CCSE_ICU_LIBRARY must be an absolute path";
      return;
    }
    int abi = 0;
    const std::string_view abi_text(explicit_abi);
    const auto parsed =
        std::from_chars(abi_text.data(), abi_text.data() + abi_text.size(), abi);
    if (parsed.ec != std::errc{} || parsed.ptr != abi_text.data() + abi_text.size() ||
        abi < 1 || abi > 999) {
      provider_detail_ = "CPH_CCSE_ICU_ABI must be a decimal integer from 1 to 999";
      return;
    }
    (void)load_candidate(library_path.string(), abi, true);
    return;
  }

  if (!ambient_enabled) {
    provider_detail_ =
        "no explicit ICU provider selected; set CPH_CCSE_ICU_LIBRARY and "
        "CPH_CCSE_ICU_ABI, or opt into provisional development discovery with "
        "CPH_CCSE_ALLOW_AMBIENT_ICU=1";
    return;
  }
  for (int abi = 90; abi >= 60; --abi) {
    const std::string library_name = "libicuuc.so." + std::to_string(abi);
    if (load_candidate(library_name, abi, false) && exact_icu_72_1() &&
        exact_unicode_15()) {
      break;
    }
  }
  if (library_ == nullptr) {
    provider_detail_ = "no usable ambient ICU normalization runtime found";
  }
}

NfcChecker::~NfcChecker() {
  if (library_ != nullptr) dlclose(library_);
}

bool NfcChecker::has_provider() const noexcept { return library_ != nullptr; }

bool NfcChecker::explicit_provider() const noexcept { return explicit_provider_; }

bool NfcChecker::conformance_ready() const noexcept {
  return explicit_provider() && exact_icu_72_1() && exact_unicode_15();
}

bool NfcChecker::exact_icu_72_1() const noexcept {
  return icu_version_ == "72.1.0";
}

bool NfcChecker::exact_unicode_15() const noexcept {
  return unicode_version_ == "15.0.0";
}

const std::string& NfcChecker::icu_version() const noexcept { return icu_version_; }

const std::string& NfcChecker::unicode_version() const noexcept {
  return unicode_version_;
}

const std::string& NfcChecker::provider_detail() const noexcept {
  return provider_detail_;
}

bool NfcChecker::is_normalized(std::string_view value) const {
  if (!has_provider()) fail("UNICODE_BLOCKER", provider_detail_);
  const auto utf16 = utf8_to_utf16(value);
  std::int32_t error = 0;
  const std::int8_t result = is_normalized_(normalizer_, utf16.data(),
                                            static_cast<std::int32_t>(utf16.size()),
                                            &error);
  if (error > 0) fail("UNICODE_FAILURE", "ICU normalization check failed");
  return result != 0;
}

PositiveFixture parse_positive_fixture(const strict_json::Value& root) {
  strict_json::expect_keys(
      root, "positive", {"vector_id", "status", "encoding", "message_type_scope",
                          "message_type_id", "schema_version", "private_key_seed_hex",
                          "domain", "envelope", "payload_projection", "expected"});
  const auto encoding = strict_json::member(root, "encoding", "positive")
                            .as_string("positive.encoding");
  if (encoding != "CPH Canonical Signing Encoding v1") {
    throw strict_json::Error("positive.encoding: unsupported encoding");
  }
  (void)strict_json::member(root, "message_type_scope", "positive")
      .as_string("positive.message_type_scope");

  PositiveFixture output;
  output.vector_id = strict_json::member(root, "vector_id", "positive")
                         .as_string("positive.vector_id");
  output.status = strict_json::member(root, "status", "positive")
                      .as_string("positive.status");
  output.message_type_id = checked_u32(
      strict_json::member(root, "message_type_id", "positive"),
      "positive.message_type_id");
  output.schema_version = parse_version(
      strict_json::member(root, "schema_version", "positive"),
      "positive.schema_version");
  output.private_key_seed = decode_hex(
      strict_json::member(root, "private_key_seed_hex", "positive")
          .as_string("positive.private_key_seed_hex"),
      "positive.private_key_seed_hex");
  if (output.private_key_seed.size() != 32) {
    throw strict_json::Error("positive.private_key_seed_hex: expected 32 bytes");
  }

  const auto& domain = strict_json::member(root, "domain", "positive");
  strict_json::expect_keys(
      domain, "positive.domain",
      {"purpose", "sender_identity", "audience_set_unsorted",
       "tenant_organization", "provider_organization", "chain_id_uint256_hex",
       "genesis_hash_hex", "environment", "protocol_version",
       "signature_algorithm_id", "signature_key_id", "issued_at_unix_nano",
       "expires_at_unix_nano", "counter_kind", "counter", "replay_domain_id"});
  output.domain.purpose = strict_json::member(domain, "purpose", "positive.domain")
                              .as_string("positive.domain.purpose");
  output.domain.sender_identity =
      strict_json::member(domain, "sender_identity", "positive.domain")
          .as_string("positive.domain.sender_identity");
  output.domain.audience = parse_string_array(
      strict_json::member(domain, "audience_set_unsorted", "positive.domain"),
      "positive.domain.audience_set_unsorted");
  output.domain.tenant_organization = parse_optional_string(
      strict_json::member(domain, "tenant_organization", "positive.domain"),
      "positive.domain.tenant_organization");
  output.domain.provider_organization = parse_optional_string(
      strict_json::member(domain, "provider_organization", "positive.domain"),
      "positive.domain.provider_organization");
  output.domain.chain_id = decode_fixed<32>(
      strict_json::member(domain, "chain_id_uint256_hex", "positive.domain")
          .as_string("positive.domain.chain_id_uint256_hex"),
      "positive.domain.chain_id_uint256_hex");
  output.domain.genesis_hash = decode_fixed<32>(
      strict_json::member(domain, "genesis_hash_hex", "positive.domain")
          .as_string("positive.domain.genesis_hash_hex"),
      "positive.domain.genesis_hash_hex");
  output.domain.environment =
      strict_json::member(domain, "environment", "positive.domain")
          .as_string("positive.domain.environment");
  output.domain.protocol_version = parse_version(
      strict_json::member(domain, "protocol_version", "positive.domain"),
      "positive.domain.protocol_version");
  output.domain.schema_version = output.schema_version;
  output.domain.signature_algorithm = checked_u32(
      strict_json::member(domain, "signature_algorithm_id", "positive.domain"),
      "positive.domain.signature_algorithm_id");
  output.domain.signature_key_id =
      strict_json::member(domain, "signature_key_id", "positive.domain")
          .as_string("positive.domain.signature_key_id");
  output.domain.issued_at_unix_nano =
      strict_json::member(domain, "issued_at_unix_nano", "positive.domain")
          .as_i64("positive.domain.issued_at_unix_nano");
  output.domain.expires_at_unix_nano =
      strict_json::member(domain, "expires_at_unix_nano", "positive.domain")
          .as_i64("positive.domain.expires_at_unix_nano");
  output.domain.counter_kind = checked_u32(
      strict_json::member(domain, "counter_kind", "positive.domain"),
      "positive.domain.counter_kind");
  output.domain.counter =
      strict_json::member(domain, "counter", "positive.domain")
          .as_u64("positive.domain.counter");
  output.domain.replay_domain_id =
      strict_json::member(domain, "replay_domain_id", "positive.domain")
          .as_string("positive.domain.replay_domain_id");

  const auto& envelope = strict_json::member(root, "envelope", "positive");
  strict_json::expect_keys(envelope, "positive.envelope",
                           {"message_id_hex", "correlation_id_hex", "causation_id",
                            "extensions"});
  output.envelope.protocol_version = output.domain.protocol_version;
  output.envelope.schema_version = output.schema_version;
  output.envelope.message_id = decode_fixed<16>(
      strict_json::member(envelope, "message_id_hex", "positive.envelope")
          .as_string("positive.envelope.message_id_hex"),
      "positive.envelope.message_id_hex");
  output.envelope.correlation_id = decode_fixed<16>(
      strict_json::member(envelope, "correlation_id_hex", "positive.envelope")
          .as_string("positive.envelope.correlation_id_hex"),
      "positive.envelope.correlation_id_hex");
  const auto& causation =
      strict_json::member(envelope, "causation_id", "positive.envelope");
  strict_json::expect_keys(causation, "positive.envelope.causation_id",
                           {"present", "value_hex"});
  output.envelope.causation_id.present =
      strict_json::member(causation, "present", "positive.envelope.causation_id")
          .as_bool("positive.envelope.causation_id.present");
  const auto causation_hex =
      strict_json::member(causation, "value_hex", "positive.envelope.causation_id")
          .as_string("positive.envelope.causation_id.value_hex");
  if (output.envelope.causation_id.present) {
    output.envelope.causation_id.value = decode_fixed<16>(
        causation_hex, "positive.envelope.causation_id.value_hex");
  } else if (!causation_hex.empty()) {
    throw strict_json::Error(
        "positive.envelope.causation_id: absent value must be empty");
  }
  const auto& extensions =
      strict_json::member(envelope, "extensions", "positive.envelope")
          .as_array("positive.envelope.extensions");
  if (extensions.size() > kMaxExtensions) {
    throw strict_json::Error("positive.envelope.extensions: too many entries");
  }
  for (std::size_t i = 0; i < extensions.size(); ++i) {
    const std::string where = "positive.envelope.extensions[" + std::to_string(i) + "]";
    strict_json::expect_keys(extensions[i], where, {"id", "critical", "value_hex"});
    output.envelope.extensions.push_back(Extension{
        .id = checked_u32(strict_json::member(extensions[i], "id", where), where + ".id"),
        .critical = strict_json::member(extensions[i], "critical", where).as_bool(where + ".critical"),
        .value = decode_hex(strict_json::member(extensions[i], "value_hex", where).as_string(where + ".value_hex"),
                            where + ".value_hex"),
    });
  }
  output.envelope.sender_identity = output.domain.sender_identity;
  output.envelope.chain_id = output.domain.chain_id;
  output.envelope.environment = output.domain.environment;
  output.envelope.issued_at_unix_nano = output.domain.issued_at_unix_nano;
  output.envelope.expires_at_unix_nano = output.domain.expires_at_unix_nano;
  output.envelope.counter_kind = output.domain.counter_kind;
  output.envelope.counter = output.domain.counter;
  output.envelope.signature_algorithm = output.domain.signature_algorithm;
  output.envelope.signature_key_id = output.domain.signature_key_id;

  const auto& payload = strict_json::member(root, "payload_projection", "positive");
  strict_json::expect_keys(payload, "positive.payload_projection",
                           {"schema_note", "record_kind", "optional_note",
                            "sample_count", "display_name", "tags_set_unsorted",
                            "canonical_hex"});
  output.payload.schema_note =
      strict_json::member(payload, "schema_note", "positive.payload_projection")
          .as_string("positive.payload_projection.schema_note");
  output.payload.record_kind =
      strict_json::member(payload, "record_kind", "positive.payload_projection")
          .as_string("positive.payload_projection.record_kind");
  output.payload.optional_note = parse_optional_string(
      strict_json::member(payload, "optional_note", "positive.payload_projection"),
      "positive.payload_projection.optional_note");
  output.payload.sample_count =
      strict_json::member(payload, "sample_count", "positive.payload_projection")
          .as_u64("positive.payload_projection.sample_count");
  output.payload.display_name =
      strict_json::member(payload, "display_name", "positive.payload_projection")
          .as_string("positive.payload_projection.display_name");
  output.payload.tags = parse_string_array(
      strict_json::member(payload, "tags_set_unsorted", "positive.payload_projection"),
      "positive.payload_projection.tags_set_unsorted");
  output.payload.declared_canonical = decode_hex(
      strict_json::member(payload, "canonical_hex", "positive.payload_projection")
          .as_string("positive.payload_projection.canonical_hex"),
      "positive.payload_projection.canonical_hex");

  const auto& expected = strict_json::member(root, "expected", "positive");
  strict_json::expect_keys(expected, "positive.expected",
                           {"canonical_domain_hex", "canonical_envelope_hex",
                            "preimage_hex", "sha256_digest_hex",
                            "ed25519_public_key_hex", "ed25519_signature_hex"});
  output.expected.canonical_domain = decode_hex(
      strict_json::member(expected, "canonical_domain_hex", "positive.expected")
          .as_string("positive.expected.canonical_domain_hex"),
      "positive.expected.canonical_domain_hex");
  output.expected.canonical_envelope = decode_hex(
      strict_json::member(expected, "canonical_envelope_hex", "positive.expected")
          .as_string("positive.expected.canonical_envelope_hex"),
      "positive.expected.canonical_envelope_hex");
  output.expected.preimage = decode_hex(
      strict_json::member(expected, "preimage_hex", "positive.expected")
          .as_string("positive.expected.preimage_hex"),
      "positive.expected.preimage_hex");
  output.expected.digest = decode_fixed<32>(
      strict_json::member(expected, "sha256_digest_hex", "positive.expected")
          .as_string("positive.expected.sha256_digest_hex"),
      "positive.expected.sha256_digest_hex");
  output.expected.public_key = decode_hex(
      strict_json::member(expected, "ed25519_public_key_hex", "positive.expected")
          .as_string("positive.expected.ed25519_public_key_hex"),
      "positive.expected.ed25519_public_key_hex");
  output.expected.signature = decode_hex(
      strict_json::member(expected, "ed25519_signature_hex", "positive.expected")
          .as_string("positive.expected.ed25519_signature_hex"),
      "positive.expected.ed25519_signature_hex");
  if (output.expected.public_key.size() != 32 || output.expected.signature.size() != 64) {
    throw strict_json::Error("positive.expected: invalid Ed25519 key/signature width");
  }
  return output;
}

NegativeFixture parse_negative_fixture(const strict_json::Value& root) {
  strict_json::expect_keys(root, "negative",
                           {"vector_set_id", "base_vector_id", "status", "cases"});
  NegativeFixture output;
  output.vector_set_id = strict_json::member(root, "vector_set_id", "negative")
                             .as_string("negative.vector_set_id");
  output.base_vector_id = strict_json::member(root, "base_vector_id", "negative")
                              .as_string("negative.base_vector_id");
  output.status = strict_json::member(root, "status", "negative")
                      .as_string("negative.status");
  const auto& cases = strict_json::member(root, "cases", "negative")
                          .as_array("negative.cases");
  if (cases.empty() || cases.size() > 256) {
    throw strict_json::Error("negative.cases: invalid case count");
  }
  std::vector<std::string> ids;
  for (std::size_t i = 0; i < cases.size(); ++i) {
    const std::string where = "negative.cases[" + std::to_string(i) + "]";
    strict_json::expect_keys(
        cases[i], where, {"id", "operation"},
        {"path", "value", "value_hex", "unix_nano", "extension_id", "critical",
         "revoked_at_unix_nano", "new_key_id", "new_private_key_seed_hex",
         "expected_error", "expected_result"});
    NegativeCase item;
    item.id = strict_json::member(cases[i], "id", where).as_string(where + ".id");
    item.operation = strict_json::member(cases[i], "operation", where)
                         .as_string(where + ".operation");
    const auto& object = cases[i].as_object(where);
    if (const auto found = object.find("path"); found != object.end()) {
      item.path = found->second.as_string(where + ".path");
    }
    if (const auto found = object.find("value"); found != object.end()) {
      item.value = found->second;
      item.has_value = true;
    }
    if (const auto found = object.find("value_hex"); found != object.end()) {
      item.value_hex = found->second.as_string(where + ".value_hex");
      item.has_value_hex = true;
    }
    if (const auto found = object.find("unix_nano"); found != object.end()) {
      item.unix_nano = found->second.as_i64(where + ".unix_nano");
      item.has_unix_nano = true;
    }
    if (const auto found = object.find("extension_id"); found != object.end()) {
      item.extension_id = checked_u32(found->second, where + ".extension_id");
      item.has_extension_id = true;
    }
    if (const auto found = object.find("critical"); found != object.end()) {
      item.critical = found->second.as_bool(where + ".critical");
      item.has_critical = true;
    }
    if (const auto found = object.find("revoked_at_unix_nano"); found != object.end()) {
      item.revoked_at_unix_nano =
          found->second.as_i64(where + ".revoked_at_unix_nano");
      item.has_revoked_at = true;
    }
    if (const auto found = object.find("new_key_id"); found != object.end()) {
      item.new_key_id = found->second.as_string(where + ".new_key_id");
    }
    if (const auto found = object.find("new_private_key_seed_hex");
        found != object.end()) {
      item.new_private_key_seed_hex =
          found->second.as_string(where + ".new_private_key_seed_hex");
    }
    if (const auto found = object.find("expected_error"); found != object.end()) {
      item.expected_error = found->second.as_string(where + ".expected_error");
    }
    if (const auto found = object.find("expected_result"); found != object.end()) {
      item.expected_result = found->second.as_string(where + ".expected_result");
    }
    if (item.id.empty() || item.operation.empty() ||
        (item.expected_error.empty() == item.expected_result.empty())) {
      throw strict_json::Error(where + ": invalid required/expected fields");
    }
    if (std::find(ids.begin(), ids.end(), item.id) != ids.end()) {
      throw strict_json::Error(where + ": duplicate case id");
    }
    ids.push_back(item.id);
    output.cases.push_back(std::move(item));
  }
  return output;
}

Bytes canonical_payload(const Payload& payload, const NfcChecker& nfc) {
  Encoder encoder(nfc);
  encoder.string(payload.record_kind);
  encoder.optional_string(payload.optional_note);
  encoder.u64(payload.sample_count);
  encoder.string(payload.display_name);
  encoder.string_set(payload.tags);
  return std::move(encoder).finish();
}

Bytes canonical_domain(const Domain& domain, const NfcChecker& nfc) {
  if (domain.purpose.empty() || domain.sender_identity.empty() ||
      domain.audience.empty() || domain.environment.empty() ||
      domain.signature_key_id.empty() || domain.replay_domain_id.empty()) {
    fail("INVALID_RECORD", "empty required domain field");
  }
  if (domain.audience.size() > kMaxAudience) fail("TOO_MANY_ELEMENTS", "audience set too large");
  if (all_zero(domain.chain_id) || all_zero(domain.genesis_hash)) {
    fail("INVALID_RECORD", "zero chain ID or genesis hash");
  }
  if (domain.protocol_version.major == 0 || domain.schema_version.major == 0 ||
      domain.signature_algorithm == 0) {
    fail("INVALID_RECORD_UNSPECIFIED_ALGORITHM", "invalid version or algorithm");
  }
  if (domain.counter_kind != 1 && domain.counter_kind != 2) {
    fail("INVALID_RECORD", "invalid counter kind");
  }
  if (domain.issued_at_unix_nano < 0 ||
      domain.expires_at_unix_nano <= domain.issued_at_unix_nano) {
    fail("INVALID_RECORD", "invalid validity window");
  }
  Encoder encoder(nfc);
  encoder.string(domain.purpose);
  encoder.string(domain.sender_identity);
  encoder.string_set(domain.audience);
  encoder.optional_string(domain.tenant_organization);
  encoder.optional_string(domain.provider_organization);
  encoder.fixed(domain.chain_id);
  encoder.fixed(domain.genesis_hash);
  encoder.string(domain.environment);
  encode_version(encoder, domain.protocol_version);
  encode_version(encoder, domain.schema_version);
  encoder.u32(domain.signature_algorithm);
  encoder.string(domain.signature_key_id);
  encoder.i64(domain.issued_at_unix_nano);
  encoder.i64(domain.expires_at_unix_nano);
  encoder.u32(domain.counter_kind);
  encoder.u64(domain.counter);
  encoder.string(domain.replay_domain_id);
  return std::move(encoder).finish();
}

Bytes canonical_envelope(const Envelope& envelope, const NfcChecker& nfc) {
  if (envelope.sender_identity.empty() || envelope.environment.empty() ||
      envelope.signature_key_id.empty() || all_zero(envelope.chain_id) ||
      all_zero(envelope.message_id) || all_zero(envelope.correlation_id)) {
    fail("INVALID_RECORD", "empty required envelope field");
  }
  if ((!envelope.causation_id.present && !all_zero(envelope.causation_id.value)) ||
      (envelope.causation_id.present && all_zero(envelope.causation_id.value))) {
    fail("NON_CANONICAL_ABSENT", "invalid causation presence/value");
  }
  if (envelope.extensions.size() > kMaxExtensions) {
    fail("TOO_MANY_ELEMENTS", "extension list too large");
  }
  if (envelope.protocol_version.major == 0 || envelope.schema_version.major == 0 ||
      envelope.signature_algorithm == 0) {
    fail("INVALID_RECORD_UNSPECIFIED_ALGORITHM", "invalid version or algorithm");
  }
  if (envelope.counter_kind != 1 && envelope.counter_kind != 2) {
    fail("INVALID_RECORD", "invalid counter kind");
  }
  if (envelope.issued_at_unix_nano < 0 ||
      envelope.expires_at_unix_nano <= envelope.issued_at_unix_nano) {
    fail("INVALID_RECORD", "invalid validity window");
  }
  std::vector<Extension> ordered = envelope.extensions;
  std::sort(ordered.begin(), ordered.end(),
            [](const Extension& left, const Extension& right) { return left.id < right.id; });
  std::vector<Bytes> encoded_extensions;
  for (std::size_t i = 0; i < ordered.size(); ++i) {
    if (ordered[i].id == 0) fail("INVALID_EXTENSION", "zero extension id");
    if (i != 0 && ordered[i - 1].id == ordered[i].id) {
      fail("DUPLICATE_EXTENSION", "duplicate extension id");
    }
    Encoder extension(nfc);
    extension.u32(ordered[i].id);
    extension.boolean(ordered[i].critical);
    extension.bytes(ordered[i].value);
    encoded_extensions.push_back(std::move(extension).finish());
  }

  Encoder encoder(nfc);
  encode_version(encoder, envelope.protocol_version);
  encode_version(encoder, envelope.schema_version);
  encoder.fixed(envelope.message_id);
  encoder.fixed(envelope.correlation_id);
  encoder.boolean(envelope.causation_id.present);
  if (envelope.causation_id.present) encoder.fixed(envelope.causation_id.value);
  encoder.string(envelope.sender_identity);
  encoder.fixed(envelope.chain_id);
  encoder.string(envelope.environment);
  encoder.i64(envelope.issued_at_unix_nano);
  encoder.i64(envelope.expires_at_unix_nano);
  encoder.u32(envelope.counter_kind);
  encoder.u64(envelope.counter);
  encoder.fixed(envelope.payload_digest);
  encoder.u32(envelope.signature_algorithm);
  encoder.string(envelope.signature_key_id);
  encoder.encoded_list(encoded_extensions);
  return std::move(encoder).finish();
}

void validate_record(const Record& record, const NfcChecker& nfc) {
  if (record.message_type_id == 0 || record.schema_version.major == 0) {
    fail("INVALID_RECORD", "zero message type or schema major");
  }
  if (!(record.schema_version == record.domain.schema_version) ||
      !(record.schema_version == record.envelope.schema_version)) {
    fail("DOMAIN_ENVELOPE_MISMATCH", "schema version mismatch");
  }
  (void)canonical_domain(record.domain, nfc);
  (void)canonical_envelope(record.envelope, nfc);
  const Domain& d = record.domain;
  const Envelope& e = record.envelope;
  if (!(d.protocol_version == e.protocol_version) ||
      !(d.schema_version == e.schema_version) ||
      d.sender_identity != e.sender_identity || d.chain_id != e.chain_id ||
      d.environment != e.environment ||
      d.issued_at_unix_nano != e.issued_at_unix_nano ||
      d.expires_at_unix_nano != e.expires_at_unix_nano ||
      d.counter_kind != e.counter_kind || d.counter != e.counter ||
      d.signature_algorithm != e.signature_algorithm ||
      d.signature_key_id != e.signature_key_id) {
    fail("DOMAIN_ENVELOPE_MISMATCH", "domain/envelope binding mismatch");
  }
  if (sha256(record.payload) != e.payload_digest) {
    fail("PAYLOAD_DIGEST_MISMATCH", "payload digest mismatch");
  }
}

Bytes preimage(const Record& record, const NfcChecker& nfc) {
  validate_record(record, nfc);
  const Bytes domain = canonical_domain(record.domain, nfc);
  const Bytes envelope = canonical_envelope(record.envelope, nfc);
  Bytes output;
  output.reserve(kPreamble.size() + 12 + 4 + domain.size() + 8 + envelope.size() +
                 8 + record.payload.size());
  output.insert(output.end(), kPreamble.begin(), kPreamble.end());
  auto append_u32 = [&output](std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 24));
    output.push_back(static_cast<std::uint8_t>(value >> 16));
    output.push_back(static_cast<std::uint8_t>(value >> 8));
    output.push_back(static_cast<std::uint8_t>(value));
  };
  auto append_u64 = [&output](std::uint64_t value) {
    std::array<std::uint8_t, 8> encoded{};
    for (int i = 7; i >= 0; --i) {
      encoded[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(value);
      value >>= 8;
    }
    output.insert(output.end(), encoded.begin(), encoded.end());
  };
  append_u32(record.message_type_id);
  append_u32(record.schema_version.major);
  append_u32(record.schema_version.minor);
  append_u32(static_cast<std::uint32_t>(domain.size()));
  output.insert(output.end(), domain.begin(), domain.end());
  append_u64(envelope.size());
  output.insert(output.end(), envelope.begin(), envelope.end());
  append_u64(record.payload.size());
  output.insert(output.end(), record.payload.begin(), record.payload.end());
  return output;
}

Bytes ed25519_public_from_seed(std::span<const std::uint8_t> seed) {
  if (seed.size() != 32) fail("CRYPTO_FAILURE", "Ed25519 seed must be 32 bytes");
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
      EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr, seed.data(),
                                      seed.size()),
      EVP_PKEY_free);
  if (!key) fail("CRYPTO_FAILURE", openssl_error());
  Bytes output(32);
  std::size_t size = output.size();
  if (EVP_PKEY_get_raw_public_key(key.get(), output.data(), &size) != 1 ||
      size != output.size()) {
    fail("CRYPTO_FAILURE", openssl_error());
  }
  return output;
}

Bytes ed25519_sign_digest(std::span<const std::uint8_t> seed,
                          std::span<const std::uint8_t> digest) {
  if (seed.size() != 32 || digest.size() != 32) {
    fail("CRYPTO_FAILURE", "invalid Ed25519 seed or digest width");
  }
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
      EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr, seed.data(),
                                      seed.size()),
      EVP_PKEY_free);
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(),
                                                                 EVP_MD_CTX_free);
  if (!key || !context ||
      EVP_DigestSignInit_ex(context.get(), nullptr, nullptr, nullptr, nullptr,
                            key.get(), nullptr) != 1) {
    fail("CRYPTO_FAILURE", openssl_error());
  }
  Bytes signature(64);
  std::size_t signature_size = signature.size();
  if (EVP_DigestSign(context.get(), signature.data(), &signature_size, digest.data(),
                     digest.size()) != 1 ||
      signature_size != signature.size()) {
    fail("CRYPTO_FAILURE", openssl_error());
  }
  return signature;
}

bool ed25519_verify_digest(std::span<const std::uint8_t> public_key,
                           std::span<const std::uint8_t> digest,
                           std::span<const std::uint8_t> signature) {
  if (public_key.size() != 32 || digest.size() != 32 || signature.size() != 64) {
    return false;
  }
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
      EVP_PKEY_new_raw_public_key_ex(nullptr, "ED25519", nullptr, public_key.data(),
                                     public_key.size()),
      EVP_PKEY_free);
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(),
                                                                 EVP_MD_CTX_free);
  if (!key || !context ||
      EVP_DigestVerifyInit_ex(context.get(), nullptr, nullptr, nullptr, nullptr,
                              key.get(), nullptr) != 1) {
    fail("CRYPTO_FAILURE", openssl_error());
  }
  const int result = EVP_DigestVerify(context.get(), signature.data(), signature.size(),
                                      digest.data(), digest.size());
  if (result < 0) fail("CRYPTO_FAILURE", openssl_error());
  return result == 1;
}

Record make_base_record(const PositiveFixture& fixture, const NfcChecker& nfc) {
  Record record{
      .message_type_id = fixture.message_type_id,
      .schema_version = fixture.schema_version,
      .domain = fixture.domain,
      .envelope = fixture.envelope,
      .payload = canonical_payload(fixture.payload, nfc),
      .signature = fixture.expected.signature,
  };
  record.envelope.payload_digest = sha256(record.payload);
  return record;
}

void resign(Record& record, std::span<const std::uint8_t> seed,
            const NfcChecker& nfc) {
  record.envelope.payload_digest = sha256(record.payload);
  record.signature = ed25519_sign_digest(seed, sha256(preimage(record, nfc)));
}

}  // namespace cph::ccse
