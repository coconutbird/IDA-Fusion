#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

// Mock IDA SDK functions for testing
#define qsnprintf snprintf

// Include settings first (it defines the flags)
#include "fusion/settings.h"

// Now include the signature header (without __IDP__ so no IDA deps)
#include "fusion/signature.h"

// Include the implementation directly for testing
// (We can't link against the real .cpp because it has IDA dependencies)
#include <sstream>

namespace fusion {
void SignatureBuilder::clear() {
  bytes_.clear();
  wildcards_.clear();
}

void SignatureBuilder::add_byte(uint8_t byte, bool is_wildcard) {
  bytes_.push_back(byte);
  wildcards_.push_back(is_wildcard);
}

void SignatureBuilder::trim_wildcards() {
  while (!wildcards_.empty() && wildcards_.back()) {
    bytes_.pop_back();
    wildcards_.pop_back();
  }
  while (!wildcards_.empty() && wildcards_.front()) {
    bytes_.erase(bytes_.begin());
    wildcards_.erase(wildcards_.begin());
  }
}

std::string SignatureBuilder::render(SignatureStyle style) const {
  switch (style) {
  case SignatureStyle::Code:
    return render_code();
  case SignatureStyle::IDA:
    return render_ida();
  case SignatureStyle::FNV1A: {
    char buf[16];
    qsnprintf(buf, sizeof(buf), "0x%08X", hash_fnv1a());
    return buf;
  }
  case SignatureStyle::CRC32: {
    char buf[16];
    qsnprintf(buf, sizeof(buf), "0x%08X", hash_crc32());
    return buf;
  }
  }
  return {};
}

std::string SignatureBuilder::render_code() const {
  std::ostringstream ss;
  const char* wildcard = g_settings.has(UseAltWildcard) ? "\\x2A" : "\\x00";
  for (size_t i = 0; i < bytes_.size(); ++i) {
    if (wildcards_[i]) {
      ss << wildcard;
    } else {
      char buf[8];
      qsnprintf(buf, sizeof(buf), "\\x%02X", bytes_[i]);
      ss << buf;
    }
  }
  if (g_settings.has(IncludeMask)) {
    ss << ' ';
    for (bool wc : wildcards_)
      ss << (wc ? '?' : 'x');
  }
  return ss.str();
}

std::string SignatureBuilder::render_ida() const {
  std::ostringstream ss;
  const char* wildcard = g_settings.has(UseDoubleWildcard) ? "??" : "?";
  for (size_t i = 0; i < bytes_.size(); ++i) {
    if (i > 0) ss << ' ';
    if (wildcards_[i]) {
      ss << wildcard;
    } else {
      char buf[4];
      qsnprintf(buf, sizeof(buf), "%02X", bytes_[i]);
      ss << buf;
    }
  }
  return ss.str();
}

uint32_t SignatureBuilder::hash_fnv1a() const {
  uint32_t hash = 0x811c9dc5;
  for (uint8_t byte : bytes_)
    hash = (hash ^ byte) * 0x01000193;
  return hash;
}

uint32_t SignatureBuilder::hash_crc32() const {
  uint32_t crc = 0xFFFFFFFF;
  for (uint8_t byte : bytes_) {
    crc ^= byte;
    for (int i = 0; i < 8; ++i)
      crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
  }
  return ~crc;
}
} // namespace fusion

// ============================================================================
// Tests
// ============================================================================

TEST_CASE("SignatureBuilder basics") {
  fusion::SignatureBuilder builder;

  CHECK(builder.empty());
  CHECK(builder.size() == 0);

  builder.add_byte(0x48, false);
  builder.add_byte(0x89, false);
  builder.add_byte(0x5C, false);

  CHECK_FALSE(builder.empty());
  CHECK(builder.size() == 3);

  builder.clear();
  CHECK(builder.empty());
}

TEST_CASE("SignatureBuilder render IDA style") {
  fusion::SignatureBuilder builder;
  builder.add_byte(0x48, false);
  builder.add_byte(0x89, false);
  builder.add_byte(0x00, true); // wildcard
  builder.add_byte(0x24, false);

  CHECK(builder.render(fusion::SignatureStyle::IDA) == "48 89 ? 24");
}

TEST_CASE("SignatureBuilder render CODE style") {
  fusion::SignatureBuilder builder;
  builder.add_byte(0x48, false);
  builder.add_byte(0x89, false);
  builder.add_byte(0x00, true); // wildcard

  CHECK(builder.render(fusion::SignatureStyle::Code) == "\\x48\\x89\\x00");
}

TEST_CASE("SignatureBuilder trim wildcards") {
  fusion::SignatureBuilder builder;
  builder.add_byte(0x00, true); // leading wildcard
  builder.add_byte(0x48, false);
  builder.add_byte(0x89, false);
  builder.add_byte(0x00, true); // trailing wildcard

  builder.trim_wildcards();

  CHECK(builder.size() == 2);
  CHECK(builder.render(fusion::SignatureStyle::IDA) == "48 89");
}

TEST_CASE("SignatureBuilder hash functions") {
  fusion::SignatureBuilder builder;
  builder.add_byte(0x48, false);
  builder.add_byte(0x89, false);
  builder.add_byte(0x5C, false);

  // Just verify they produce consistent output
  uint32_t fnv = builder.hash_fnv1a();
  uint32_t crc = builder.hash_crc32();

  CHECK(fnv != 0);
  CHECK(crc != 0);
  CHECK(fnv != crc);

  // Verify render produces hex strings
  CHECK(builder.render(fusion::SignatureStyle::FNV1A).substr(0, 2) == "0x");
  CHECK(builder.render(fusion::SignatureStyle::CRC32).substr(0, 2) == "0x");
}
