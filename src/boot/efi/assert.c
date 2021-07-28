/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef NDEBUG

#include <efi.h>
#include <efilib.h>
#include "util.h"

void efi_assert(const char *expr, const char *file, unsigned line, const char *function) {
      PrintErrorStall(L"Systemd-boot assertion '%a' failed at %a:%u, function %a(). Halting.", expr, file, line, function);
      for (;;)
            uefi_call_wrapper(BS->Stall, 1, UINTN_MAX);
}

#endif
