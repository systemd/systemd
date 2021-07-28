/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifdef EFI_DEBUG

#include <efi.h>
#include <efilib.h>
#include "util.h"

void efi_assert(const char *expr, const char *file, unsigned line) {
      PrintErrorStall(L"\nASSERT FAILED in %a:%u: %a\n"
                      L"Please file a bug report. Halting.\n",
                      file, line, expr);
      for (;;)
            uefi_call_wrapper(BS->Stall, 1, UINTN_MAX);
}
#endif
