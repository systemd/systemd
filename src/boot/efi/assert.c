/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifdef EFI_DEBUG

#include <efi.h>
#include <efilib.h>

void efi_assert(const char *expr, const char *file, unsigned int line) {
      uefi_call_wrapper(ST->ConOut->SetAttribute, 2, ST->ConOut, EFI_LIGHTRED|EFI_BACKGROUND_BLACK);
      Print(L"\nASSERT FAILED in %a:%u: %a\n"
            L"Please file a bug report. Trying to continue in 30s.\n",
            file, line, expr);
      uefi_call_wrapper(BS->Stall, 1, 30 * 1000 * 1000);
}
#endif
