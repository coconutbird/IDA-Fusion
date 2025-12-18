#include "fusion/signature.h"
#include "fusion/settings.h"
#include "fusion/utils.h"

#include <bytes.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <search.hpp>

#include <regex>
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
  // Remove trailing wildcards
  while (!wildcards_.empty() && wildcards_.back()) {
    bytes_.pop_back();
    wildcards_.pop_back();
  }
  // Remove leading wildcards
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
  const auto& settings = g_settings;
  const char* wildcard = settings.has(UseAltWildcard) ? "\\x2A" : "\\x00";

  for (size_t i = 0; i < bytes_.size(); ++i) {
    if (wildcards_[i]) {
      ss << wildcard;
    } else {
      char buf[8];
      qsnprintf(buf, sizeof(buf), "\\x%02X", bytes_[i]);
      ss << buf;
    }
  }

  // Append mask if enabled
  if (settings.has(IncludeMask)) {
    ss << ' ';
    for (bool wc : wildcards_) {
      ss << (wc ? '?' : 'x');
    }
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
  for (uint8_t byte : bytes_) {
    hash = (hash ^ byte) * 0x01000193;
  }
  return hash;
}

uint32_t SignatureBuilder::hash_crc32() const {
  uint32_t crc = 0xFFFFFFFF;
  for (uint8_t byte : bytes_) {
    crc ^= byte;
    for (int i = 0; i < 8; ++i) {
      crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
  }
  return ~crc;
}

// Convert CODE-style signature to IDA-style for searching
static std::string normalize_pattern(std::string pattern) {
  if (pattern.find("\\x") == std::string::npos) {
    return pattern;
  }

  // Convert \x to space, remove mask chars, convert 00 to ?
  pattern = std::regex_replace(pattern, std::regex("\\\\x"), " ");
  pattern = std::regex_replace(pattern, std::regex("[x?]"), "");
  pattern = std::regex_replace(pattern, std::regex("00"), "?");

  // Trim leading space
  if (!pattern.empty() && pattern[0] == ' ') {
    pattern.erase(0, 1);
  }
  return pattern;
}

std::vector<ea_t> find_signature(const std::string& pattern, const FindSettings& settings) {
  std::vector<ea_t> results;
  const std::string normalized = normalize_pattern(pattern);

  if (!settings.silent) {
    hide_wait_box();
    show_wait_box("[Fusion] Searching...");
  }

  auto [ea_min, ea_max] = utils::get_address_range();
  ea_t addr = (settings.start_addr > 0 ? static_cast<ea_t>(settings.start_addr) : ea_min) - 1;

#if IDA_SDK_VERSION >= 900
  compiled_binpat_vec_t compiled;
  parse_binpat_str(&compiled, addr, normalized.c_str(), 16);
#endif

  while (true) {
#if IDA_SDK_VERSION >= 900
    addr = bin_search(addr + 1, ea_max, compiled, BIN_SEARCH_NOCASE | BIN_SEARCH_FORWARD);
#else
    addr = find_binary(addr + 1, ea_max, normalized.c_str(), 16, SEARCH_DOWN);
#endif

    if (addr == 0 || addr == BADADDR) break;
    if (addr == static_cast<ea_t>(settings.ignore_addr)) continue;

    if (settings.jump_to_found && results.empty()) {
      jumpto(addr);
    }

    results.push_back(addr);

    if (!settings.silent) {
      replace_wait_box(
          "[Fusion] Found %zu match%s", results.size(), results.size() > 1 ? "es" : "");
      msg("[Fusion] %zu. Found at 0x%llX\n", results.size(), static_cast<uint64_t>(addr));
    }

    if (settings.stop_at_first) break;
  }

  if (!settings.silent) {
    hide_wait_box();
    if (results.empty()) {
      msg("[Fusion] No matches found\n");
    } else if (results.size() > 1) {
      msg("[Fusion] Found %zu matches\n", results.size());
    }
    beep(beep_default);
  }

  return results;
}

// Helper to add instruction bytes to signature builder
static void add_instruction_bytes(SignatureBuilder& builder, ea_t addr, const insn_t& insn) {
  const int imm_offset = utils::get_immediate_offset(insn);
  for (ea_t i = addr; i < addr + insn.size; ++i) {
    const bool is_wildcard = imm_offset > 0 && (i - addr) >= imm_offset;
    builder.add_byte(get_byte(i), is_wildcard);
  }
}

std::string create_signature(SignatureStyle style) {
  const ea_t target = get_screen_ea();

  // Validate we're in a valid region (get_func_num returns -1 if not in a function)
  if (!g_settings.has(AllowDangerousRegions) && get_func_num(target) == -1) {
    hide_wait_box();
    warning("[Fusion] 0x%llX is not in a valid function.\n"
            "Enable 'Allow dangerous regions' in settings to override.",
        static_cast<uint64_t>(target));
    return {};
  }

  SignatureBuilder builder;
  auto [ea_min, ea_max] = utils::get_address_range();

  ea_t region_start = 0, region_end = 0;

  // Check if user selected a range
  if (g_settings.has(UseSelectedRange)
      && read_range_selection(nullptr, &region_start, &region_end)) {
    // Build signature from selected range only
    replace_wait_box("[Fusion] Creating signature for 0x%llX", static_cast<uint64_t>(target));

    func_item_iterator_t iter;
    iter.set_range(region_start, region_end);

    for (ea_t addr = iter.current();; addr = iter.current()) {
      insn_t insn;
      if (!decode_insn(&insn, addr)) break;

      add_instruction_bytes(builder, addr, insn);

      // Handle int3/nop which IDA doesn't iterate correctly
      if (get_byte(addr) == 0xCC || get_byte(addr) == 0x90) {
        iter.set_range(addr + 1, ea_max);
        continue;
      }

      if (!iter.next_not_tail()) break;
    }
  } else {
    // Build unique signature iteratively
    ea_t last_found = ea_min;

    // Buffer for mnemonic display (if enabled)
    std::string mnemonics;

    func_item_iterator_t iter;
    iter.set_range(target, ea_max);

    for (ea_t addr = iter.current();; addr = iter.current()) {
      insn_t insn;
      if (!decode_insn(&insn, addr)) break;

      add_instruction_bytes(builder, addr, insn);

      // Show mnemonic opcodes if enabled
      if (g_settings.has(ShowMnemonics)) {
        mnemonics += "+ ";
        mnemonics += insn.get_canon_mnem(PH);
        mnemonics += "\n";
        replace_wait_box("[Fusion] Creating signature for 0x%llX\n\n%s",
            static_cast<uint64_t>(target), mnemonics.c_str());
      }

      // Check if signature is unique
      std::string test_sig = builder.render(SignatureStyle::IDA);
      auto matches = find_signature(test_sig, {true, true, target, last_found, false});

      if (matches.empty()) break; // Unique!

      last_found = matches[0];

      // Handle int3/nop
      if (get_byte(addr) == 0xCC || get_byte(addr) == 0x90) {
        iter.set_range(addr + 1, ea_max);
        continue;
      }

      if (!iter.next_not_tail()) break;
    }
  }

  if (builder.empty()) {
    return {};
  }

  builder.trim_wildcards();
  std::string result = builder.render(style);

  msg("[Fusion] %s\n", result.c_str());

  if (g_settings.has(CopyToClipboard)) {
    utils::copy_to_clipboard(result.c_str());
  }

  beep(beep_default);
  return result;
}
} // namespace fusion
