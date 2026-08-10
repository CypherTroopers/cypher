// Copyright 2026 The Cypherium Authors
// SPDX-License-Identifier: LGPL-3.0-only

#pragma once

#include <charconv>
#include <cstdint>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace strict_json {

class Error final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

struct Limits {
  std::size_t max_input_bytes = 2U << 20;
  std::size_t max_string_bytes = 1U << 20;
  std::size_t max_values = 100000;
  std::size_t max_depth = 32;
};

struct Value {
  enum class Kind { Null, Boolean, Number, String, Array, Object };

  Kind kind = Kind::Null;
  bool boolean = false;
  std::string text;
  std::vector<Value> array;
  std::map<std::string, Value, std::less<>> object;

  [[nodiscard]] const std::map<std::string, Value, std::less<>>& as_object(
      std::string_view where) const {
    if (kind != Kind::Object) {
      throw Error(std::string(where) + ": expected object");
    }
    return object;
  }

  [[nodiscard]] const std::vector<Value>& as_array(std::string_view where) const {
    if (kind != Kind::Array) {
      throw Error(std::string(where) + ": expected array");
    }
    return array;
  }

  [[nodiscard]] const std::string& as_string(std::string_view where) const {
    if (kind != Kind::String) {
      throw Error(std::string(where) + ": expected string");
    }
    return text;
  }

  [[nodiscard]] bool as_bool(std::string_view where) const {
    if (kind != Kind::Boolean) {
      throw Error(std::string(where) + ": expected boolean");
    }
    return boolean;
  }

  [[nodiscard]] std::uint64_t as_u64(std::string_view where) const {
    if (kind != Kind::Number || text.empty() || text.front() == '-' ||
        text.find_first_of(".eE+") != std::string::npos) {
      throw Error(std::string(where) + ": expected canonical unsigned integer");
    }
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
      throw Error(std::string(where) + ": unsigned integer out of range");
    }
    return result;
  }

  [[nodiscard]] std::int64_t as_i64(std::string_view where) const {
    if (kind != Kind::Number || text.empty() ||
        text.find_first_of(".eE+") != std::string::npos) {
      throw Error(std::string(where) + ": expected canonical signed integer");
    }
    std::int64_t result = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
      throw Error(std::string(where) + ": signed integer out of range");
    }
    return result;
  }
};

inline const Value& member(const Value& value, std::string_view name,
                           std::string_view where) {
  const auto& object = value.as_object(where);
  const auto found = object.find(name);
  if (found == object.end()) {
    throw Error(std::string(where) + ": missing field " + std::string(name));
  }
  return found->second;
}

inline void expect_keys(const Value& value, std::string_view where,
                        std::initializer_list<std::string_view> required,
                        std::initializer_list<std::string_view> optional = {}) {
  const auto& object = value.as_object(where);
  std::set<std::string_view> allowed;
  allowed.insert(required.begin(), required.end());
  allowed.insert(optional.begin(), optional.end());
  for (const auto& [name, ignored] : object) {
    (void)ignored;
    if (!allowed.contains(name)) {
      throw Error(std::string(where) + ": unknown field " + name);
    }
  }
  for (const auto name : required) {
    if (!object.contains(name)) {
      throw Error(std::string(where) + ": missing field " + std::string(name));
    }
  }
}

namespace detail {

inline bool valid_utf8(std::string_view input) {
  std::size_t i = 0;
  while (i < input.size()) {
    const auto first = static_cast<unsigned char>(input[i++]);
    if (first <= 0x7f) {
      continue;
    }
    std::uint32_t codepoint = 0;
    std::size_t remaining = 0;
    std::uint32_t minimum = 0;
    if (first >= 0xc2 && first <= 0xdf) {
      codepoint = first & 0x1f;
      remaining = 1;
      minimum = 0x80;
    } else if (first >= 0xe0 && first <= 0xef) {
      codepoint = first & 0x0f;
      remaining = 2;
      minimum = 0x800;
    } else if (first >= 0xf0 && first <= 0xf4) {
      codepoint = first & 0x07;
      remaining = 3;
      minimum = 0x10000;
    } else {
      return false;
    }
    if (input.size() - i < remaining) {
      return false;
    }
    for (std::size_t part = 0; part < remaining; ++part) {
      const auto next = static_cast<unsigned char>(input[i++]);
      if ((next & 0xc0) != 0x80) {
        return false;
      }
      codepoint = (codepoint << 6) | (next & 0x3f);
    }
    if (codepoint < minimum || codepoint > 0x10ffff ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
      return false;
    }
  }
  return true;
}

inline void append_utf8(std::string& output, std::uint32_t codepoint) {
  if (codepoint <= 0x7f) {
    output.push_back(static_cast<char>(codepoint));
  } else if (codepoint <= 0x7ff) {
    output.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
    output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
  } else if (codepoint <= 0xffff) {
    output.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
    output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
    output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
  } else {
    output.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
    output.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
    output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
    output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
  }
}

class Parser final {
 public:
  Parser(std::string_view input, Limits limits) : input_(input), limits_(limits) {
    if (input_.size() > limits_.max_input_bytes) {
      throw Error("JSON input exceeds configured bound");
    }
  }

  Value parse_document() {
    skip_space();
    Value value = parse_value(0);
    skip_space();
    if (position_ != input_.size()) {
      fail("trailing data");
    }
    return value;
  }

 private:
  [[noreturn]] void fail(std::string_view message) const {
    throw Error("JSON byte " + std::to_string(position_) + ": " +
                std::string(message));
  }

  void count_value() {
    if (++value_count_ > limits_.max_values) {
      fail("value count exceeds configured bound");
    }
  }

  void skip_space() {
    while (position_ < input_.size()) {
      const char current = input_[position_];
      if (current != ' ' && current != '\n' && current != '\r' && current != '\t') {
        return;
      }
      ++position_;
    }
  }

  Value parse_value(std::size_t depth) {
    if (depth > limits_.max_depth) {
      fail("nesting exceeds configured bound");
    }
    count_value();
    if (position_ >= input_.size()) {
      fail("unexpected end of input");
    }
    switch (input_[position_]) {
      case '{':
        return parse_object(depth + 1);
      case '[':
        return parse_array(depth + 1);
      case '"': {
        Value out;
        out.kind = Value::Kind::String;
        out.text = parse_string();
        return out;
      }
      case 't':
        consume_literal("true");
        return Value{.kind = Value::Kind::Boolean,
                     .boolean = true,
                     .text = {},
                     .array = {},
                     .object = {}};
      case 'f':
        consume_literal("false");
        return Value{.kind = Value::Kind::Boolean,
                     .boolean = false,
                     .text = {},
                     .array = {},
                     .object = {}};
      case 'n':
        consume_literal("null");
        return Value{};
      default:
        if (input_[position_] == '-' ||
            (input_[position_] >= '0' && input_[position_] <= '9')) {
          Value out;
          out.kind = Value::Kind::Number;
          out.text = parse_number();
          return out;
        }
        fail("unexpected token");
    }
  }

  Value parse_object(std::size_t depth) {
    ++position_;
    Value out;
    out.kind = Value::Kind::Object;
    skip_space();
    if (consume_if('}')) {
      return out;
    }
    while (true) {
      if (position_ >= input_.size() || input_[position_] != '"') {
        fail("object key must be a string");
      }
      std::string key = parse_string();
      skip_space();
      require(':');
      skip_space();
      Value value = parse_value(depth);
      if (!out.object.emplace(std::move(key), std::move(value)).second) {
        fail("duplicate object key");
      }
      skip_space();
      if (consume_if('}')) {
        return out;
      }
      require(',');
      skip_space();
    }
  }

  Value parse_array(std::size_t depth) {
    ++position_;
    Value out;
    out.kind = Value::Kind::Array;
    skip_space();
    if (consume_if(']')) {
      return out;
    }
    while (true) {
      out.array.push_back(parse_value(depth));
      skip_space();
      if (consume_if(']')) {
        return out;
      }
      require(',');
      skip_space();
    }
  }

  static std::uint32_t hex_digit(char value) {
    if (value >= '0' && value <= '9') {
      return static_cast<std::uint32_t>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
      return static_cast<std::uint32_t>(value - 'a' + 10);
    }
    if (value >= 'A' && value <= 'F') {
      return static_cast<std::uint32_t>(value - 'A' + 10);
    }
    throw Error("invalid JSON Unicode escape");
  }

  std::uint32_t parse_u16_escape() {
    if (input_.size() - position_ < 4) {
      fail("short Unicode escape");
    }
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
      value = (value << 4) | hex_digit(input_[position_++]);
    }
    return value;
  }

  std::string parse_string() {
    require('"');
    std::string out;
    while (position_ < input_.size()) {
      const auto current = static_cast<unsigned char>(input_[position_++]);
      if (current == '"') {
        if (out.size() > limits_.max_string_bytes) {
          fail("string exceeds configured bound");
        }
        if (!valid_utf8(out)) {
          fail("string is not valid UTF-8");
        }
        return out;
      }
      if (current < 0x20) {
        fail("unescaped control character in string");
      }
      if (current != '\\') {
        out.push_back(static_cast<char>(current));
        continue;
      }
      if (position_ >= input_.size()) {
        fail("short escape sequence");
      }
      switch (input_[position_++]) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          std::uint32_t codepoint = parse_u16_escape();
          if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
            if (input_.size() - position_ < 6 || input_[position_] != '\\' ||
                input_[position_ + 1] != 'u') {
              fail("high surrogate is not followed by low surrogate");
            }
            position_ += 2;
            const std::uint32_t low = parse_u16_escape();
            if (low < 0xdc00 || low > 0xdfff) {
              fail("invalid low surrogate");
            }
            codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + (low - 0xdc00);
          } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
            fail("unpaired low surrogate");
          }
          append_utf8(out, codepoint);
          break;
        }
        default:
          fail("invalid escape sequence");
      }
      if (out.size() > limits_.max_string_bytes) {
        fail("string exceeds configured bound");
      }
    }
    fail("unterminated string");
  }

  std::string parse_number() {
    const std::size_t start = position_;
    consume_if('-');
    if (position_ >= input_.size()) fail("short number");
    if (input_[position_] == '0') {
      ++position_;
      if (position_ < input_.size() && input_[position_] >= '0' &&
          input_[position_] <= '9') {
        fail("leading zero in number");
      }
    } else {
      if (input_[position_] < '1' || input_[position_] > '9') fail("invalid number");
      while (position_ < input_.size() && input_[position_] >= '0' &&
             input_[position_] <= '9') ++position_;
    }
    if (consume_if('.')) {
      const std::size_t before = position_;
      while (position_ < input_.size() && input_[position_] >= '0' &&
             input_[position_] <= '9') ++position_;
      if (position_ == before) fail("empty fractional part");
    }
    if (position_ < input_.size() &&
        (input_[position_] == 'e' || input_[position_] == 'E')) {
      ++position_;
      if (position_ < input_.size() &&
          (input_[position_] == '+' || input_[position_] == '-')) ++position_;
      const std::size_t before = position_;
      while (position_ < input_.size() && input_[position_] >= '0' &&
             input_[position_] <= '9') ++position_;
      if (position_ == before) fail("empty exponent");
    }
    return std::string(input_.substr(start, position_ - start));
  }

  void consume_literal(std::string_view literal) {
    if (input_.substr(position_, literal.size()) != literal) {
      fail("invalid literal");
    }
    position_ += literal.size();
  }

  bool consume_if(char expected) {
    if (position_ < input_.size() && input_[position_] == expected) {
      ++position_;
      return true;
    }
    return false;
  }

  void require(char expected) {
    if (!consume_if(expected)) {
      fail(std::string("expected '") + expected + "'");
    }
  }

  std::string_view input_;
  Limits limits_;
  std::size_t position_ = 0;
  std::size_t value_count_ = 0;
};

}  // namespace detail

inline Value parse(std::string_view input, Limits limits = {}) {
  return detail::Parser(input, limits).parse_document();
}

inline Value parse_file(const std::string& path, Limits limits = {}) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    throw Error("cannot open JSON fixture: " + path);
  }
  stream.seekg(0, std::ios::end);
  const auto length = stream.tellg();
  if (length < 0 || static_cast<std::uint64_t>(length) > limits.max_input_bytes) {
    throw Error("JSON fixture exceeds configured bound: " + path);
  }
  stream.seekg(0, std::ios::beg);
  std::string input(static_cast<std::size_t>(length), '\0');
  stream.read(input.data(), static_cast<std::streamsize>(input.size()));
  if (!stream && !input.empty()) {
    throw Error("cannot read JSON fixture: " + path);
  }
  return parse(input, limits);
}

}  // namespace strict_json
