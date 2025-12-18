#pragma once

#include <cstdint>

namespace fusion {
/// Configuration flags for plugin behavior
enum SettingsFlag : uint32_t {
  AutoJumpToFound = 1 << 0,
  UseSelectedRange = 1 << 1,
  ShowMnemonics = 1 << 2,
  CopyToClipboard = 1 << 3,
  IncludeMask = 1 << 4,
  AllowDangerousRegions = 1 << 5,
  StopAtFirst = 1 << 6,
  UseDoubleWildcard = 1 << 7,
  UseAltWildcard = 1 << 8,
};

/// Global settings state
struct Settings {
  uint32_t flags = AutoJumpToFound | UseSelectedRange | ShowMnemonics | CopyToClipboard;

  [[nodiscard]] bool has(SettingsFlag flag) const {
    return (flags & flag) != 0;
  }
};

/// Global settings instance
inline Settings g_settings;
} // namespace fusion
