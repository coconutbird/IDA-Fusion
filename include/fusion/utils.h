#pragma once

#include <idp.hpp>
#include <pro.h>
#include <windows.h>

namespace fusion::utils {
/// Get the immediate operand offset for an instruction (where wildcards should start)
inline int get_immediate_offset(const insn_t& insn) {
  for (int i = 0; i < UA_MAXOP; ++i) {
    const auto& op = insn.ops[i];
    if (op.type == o_void) {
      return 0;
    }
    if (op.offb > 0) {
      return op.offb;
    }
  }
  return 0;
}

/// Get the binary's address range
inline std::pair<ea_t, ea_t> get_address_range() {
  return {inf_get_min_ea(), inf_get_max_ea()};
}

/// Copy text to the Windows clipboard
inline bool copy_to_clipboard(const char* text) {
  if (!text) return false;

  const size_t len = strlen(text) + 1;
  HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, len);
  if (!mem) return false;

  void* ptr = GlobalLock(mem);
  if (!ptr) {
    GlobalFree(mem);
    return false;
  }

  memcpy(ptr, text, len);
  GlobalUnlock(mem);

  if (!OpenClipboard(nullptr)) {
    GlobalFree(mem);
    return false;
  }

  EmptyClipboard();
  SetClipboardData(CF_TEXT, mem);
  CloseClipboard();
  return true;
}
} // namespace fusion::utils
