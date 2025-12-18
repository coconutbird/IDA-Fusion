#include "fusion/plugin.h"
#include "fusion/settings.h"
#include "fusion/signature.h"

#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>

namespace fusion {
void show_settings_dialog() {
  if (ask_form("Fusion — Settings\n"
               "<#Auto jump to found signatures:C>\n"
               "<#Use selected range for signature creation:C>\n"
               "<#Show mnemonic opcodes when creating signatures:C>\n"
               "<#Copy created signatures to clipboard:C>\n"
               "<#Include mask for CODE signatures (xx??xx):C>\n"
               "<#Allow signature creation in dangerous regions:C>\n"
               "<#Stop at first match when searching:C>\n"
               "<#Use \"??\" as wildcard for IDA style:C>\n"
               "<#Use \"2A\" as wildcard for CODE style:C>>\n",
          &g_settings.flags)) {
    run_plugin();
  }
}

void run_plugin() {
  char form_str[512];
  qsnprintf(form_str,
      sizeof(form_str),
      "IDA-Fusion for %.1f+\n"
      "<#Generate CODE signature (\\x48\\x89...):R>\n"
      "<#Generate IDA signature (48 89 ? ?):R>\n"
      "<#Generate CRC-32 hash:R>\n"
      "<#Generate FNV-1a hash:R>\n"
      "<#Search for signature:R>\n"
      "<#Settings:R>>\n",
      static_cast<float>(IDA_SDK_VERSION) / 100.0f);

  static int choice = 0;
  if (!ask_form(form_str, &choice)) {
    return;
  }

  switch (choice) {
  case 0:
    show_wait_box("[Fusion] Creating CODE signature...");
    create_signature(SignatureStyle::Code);
    hide_wait_box();
    break;

  case 1:
    show_wait_box("[Fusion] Creating IDA signature...");
    create_signature(SignatureStyle::IDA);
    hide_wait_box();
    break;

  case 2:
    show_wait_box("[Fusion] Creating CRC-32 hash...");
    create_signature(SignatureStyle::CRC32);
    hide_wait_box();
    break;

  case 3:
    show_wait_box("[Fusion] Creating FNV-1a hash...");
    create_signature(SignatureStyle::FNV1A);
    hide_wait_box();
    break;

  case 4: {
    static char pattern[8192] = {};
    if (ask_form("Fusion — Search\n<Signature:A5:8192:100>", &pattern)) {
      find_signature(pattern,
          {.silent = false,
              .stop_at_first = g_settings.has(StopAtFirst),
              .ignore_addr = 0,
              .start_addr = 0,
              .jump_to_found = g_settings.has(AutoJumpToFound)});
    }
    break;
  }

  case 5:
    show_settings_dialog();
    break;

  default:
    break;
  }
}
} // namespace fusion

//------------------------------------------------------------------------------
// IDA Plugin Interface
//------------------------------------------------------------------------------

static bool idaapi plugin_run(size_t) {
  fusion::run_plugin();
  return true;
}

static plugmod_t* idaapi plugin_init() {
  return PLUGIN_OK;
}

extern "C" plugin_t PLUGIN = {IDP_INTERFACE_VERSION,
    PLUGIN_PROC,
    plugin_init,
    nullptr,
    plugin_run,
    "Fast signature scanner & creator for IDA 9.0+",
    "https://github.com/coconutbird/IDA-Fusion",
    "Fusion",
    "Ctrl-Alt-S"};
