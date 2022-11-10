/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "efivars.h"
#include "errno-util.h"
#include "factory-reset.h"
#include "initrd-util.h"
#include "parse-util.h"
#include "proc-cmdline.h"

static int parse_proc_cmdline_factory_reset(void) {
        bool b;
        int r;

        if (!in_initrd()) /* Never honour kernel command line factory reset request outside of the initrd */
                return 0;

        r = proc_cmdline_get_bool("systemd.factory_reset", &b);
        if (r < 0)
                return log_error_errno(r, "Failed to parse systemd.factory_reset kernel command line argument: %m");
        if (r == 0)
                return -ENOENT;

        if (b)
                log_notice("Honouring factory reset requested via kernel command line.");

        return b;
}

static int parse_efi_variable_factory_reset(void) {
        _cleanup_free_ char *value = NULL;
        int r;

        if (!in_initrd()) /* Never honour EFI variable factory reset request outside of the initrd */
                return 0;

        r = efi_get_variable_string(EFI_SYSTEMD_VARIABLE(FactoryReset), &value);
        if (r == -ENOENT || ERRNO_IS_NOT_SUPPORTED(r))
                return -ENOENT;
        if (r < 0)
                return log_error_errno(r, "Failed to read EFI variable FactoryReset: %m");

        r = parse_boolean(value);
        if (r < 0)
                return log_error_errno(r, "Failed to parse EFI variable FactoryReset: %m");

        if (r)
                log_notice("Factory reset requested via EFI variable FactoryReset.");

        return r;
}

int factory_reset_requested(void) {
        int r;

        r = parse_proc_cmdline_factory_reset();
        if (r != -ENOENT)
                return r;

        return parse_efi_variable_factory_reset();
}
