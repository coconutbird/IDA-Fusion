#pragma once

#include <idp.hpp>
#include <pro.h>

#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__)
#include <cstdlib>
#elif defined(__linux__)
#include <cstdlib>
#endif

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

/// Copy text to the system clipboard (cross-platform)
inline bool copy_to_clipboard(const char* text) {
  if (!text) return false;

#ifdef _WIN32
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

#elif defined(__APPLE__)
  // Use pbcopy on macOS
  FILE* pipe = popen("pbcopy", "w");
  if (!pipe) return false;
  fputs(text, pipe);
  pclose(pipe);
  return true;

#elif defined(__linux__)
  // Try xclip first, fall back to xsel
  FILE* pipe = popen("xclip -selection clipboard 2>/dev/null", "w");
  if (!pipe) {
    pipe = popen("xsel --clipboard --input 2>/dev/null", "w");
  }
  if (!pipe) return false;
  fputs(text, pipe);
  pclose(pipe);
  return true;

#else
  // Unsupported platform
  (void) text;
  return false;
#endif
}
} // namespace fusion::utils
