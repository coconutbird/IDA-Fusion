#pragma once

#include "settings.h"
#include "types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace fusion {
/// Builds signatures from instruction bytes
class SignatureBuilder {
public:
  void clear();
  void add_byte(uint8_t byte, bool is_wildcard = false);
  void trim_wildcards();

  [[nodiscard]] bool empty() const {
    return bytes_.empty();
  }
  [[nodiscard]] size_t size() const {
    return bytes_.size();
  }

  /// Render signature in the specified format
  [[nodiscard]] std::string render(SignatureStyle style) const;

  /// Generate hash of the signature bytes (non-wildcard only)
  [[nodiscard]] uint32_t hash_fnv1a() const;
  [[nodiscard]] uint32_t hash_crc32() const;

private:
  std::string render_code() const;
  std::string render_ida() const;

  std::vector<uint8_t> bytes_;
  std::vector<bool> wildcards_;
};

} // namespace fusion

// IDA-dependent declarations (only when building with IDA SDK)
#ifdef __IDP__
#include <pro.h>

namespace fusion {

/// Find all occurrences of a signature pattern
std::vector<ea_t> find_signature(const std::string& pattern, const FindSettings& settings);

/// Create a unique signature for the current cursor location
std::string create_signature(SignatureStyle style);
} // namespace fusion
#endif
