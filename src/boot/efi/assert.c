/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "util.h"

void efi_assert(const char *expr, const char *file, unsigned line, const char *function) {
        log_error("systemd-boot assertion '%s' failed at %s:%u, function %s(). Halting.",
                  expr,
                  file,
                  line,
                  function);
        for (;;)
                BS->Stall(60 * 1000 * 1000);
}
