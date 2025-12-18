#pragma once

#include <cstdint>

namespace fusion {
/// Signature output format styles
enum class SignatureStyle {
  Code,  // \x48\x89\x5C format
  IDA,   // 48 89 5C ? ? format
  FNV1A, // FNV-1a hash
  CRC32  // CRC-32 hash
};

/// Settings for signature search operations
struct FindSettings {
  bool silent = true;
  bool stop_at_first = false;
  uint64_t ignore_addr = 0;
  uint64_t start_addr = 0;
  bool jump_to_found = false;
};
} // namespace fusion
