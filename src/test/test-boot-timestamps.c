/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/types.h>
#include <unistd.h>

#include "acpi-fpdt.h"
#include "boot-timestamps.h"
#include "efi-loader.h"
#include "errno-util.h"
#include "log.h"
#include "tests.h"

static int test_acpi_fpdt(void) {
        usec_t loader_start, loader_exit;
        int r;

        r = acpi_get_boot_usec(&loader_start, &loader_exit);
        if (r < 0) {
                bool ok = IN_SET(r, -ENOENT, -ENODATA, -ERANGE) || ERRNO_IS_PRIVILEGE(r);

                log_full_errno(ok ? LOG_DEBUG : LOG_ERR, r, "Failed to read ACPI FPDT: %m");
                return ok ? 0 : r;
        }

        log_info("ACPI FPDT: loader start=%s exit=%s duration=%s",
                 FORMAT_TIMESPAN(loader_start, USEC_PER_MSEC),
                 FORMAT_TIMESPAN(loader_exit, USEC_PER_MSEC),
                 FORMAT_TIMESPAN(loader_exit - loader_start, USEC_PER_MSEC));
        return 1;
}

static int test_efi_loader(void) {
        usec_t loader_start, loader_exit;
        int r;

        r = efi_loader_get_boot_usec(&loader_start, &loader_exit);
        if (r < 0) {
                bool ok = IN_SET(r, -ENOENT, -EOPNOTSUPP) || ERRNO_IS_PRIVILEGE(r);

                log_full_errno(ok ? LOG_DEBUG : LOG_ERR, r, "Failed to read EFI loader data: %m");
                return ok ? 0 : r;
        }

        log_info("EFI Loader: start=%s exit=%s duration=%s",
                 FORMAT_TIMESPAN(loader_start, USEC_PER_MSEC),
                 FORMAT_TIMESPAN(loader_exit, USEC_PER_MSEC),
                 FORMAT_TIMESPAN(loader_exit - loader_start, USEC_PER_MSEC));
        return 1;
}

static int test_boot_timestamps(void) {
        dual_timestamp fw, l, k;
        int r;

        dual_timestamp_from_monotonic(&k, 0);

        r = boot_timestamps(NULL, &fw, &l);
        if (r < 0) {
                bool ok = IN_SET(r, -ENOENT, -EOPNOTSUPP) || ERRNO_IS_PRIVILEGE(r);

                log_full_errno(ok ? LOG_DEBUG : LOG_ERR, r, "Failed to read variables: %m");
                return ok ? 0 : r;
        }

        log_info("Firmware began %s before kernel.", FORMAT_TIMESPAN(fw.monotonic, 0));
        log_info("Loader began %s before kernel.", FORMAT_TIMESPAN(l.monotonic, 0));
        log_info("Firmware began %s.", FORMAT_TIMESTAMP(fw.realtime));
        log_info("Loader began %s.", FORMAT_TIMESTAMP(l.realtime));
        log_info("Kernel began %s.", FORMAT_TIMESTAMP(k.realtime));
        return 1;
}

int main(int argc, char* argv[]) {
        int p, q, r;

        test_setup_logging(LOG_DEBUG);

        p = test_acpi_fpdt();
        ASSERT_OK(p);
        q = test_efi_loader();
        ASSERT_OK(q);
        r = test_boot_timestamps();
        ASSERT_OK(r);

        if (p == 0 && q == 0 && r == 0)
                return log_tests_skipped("access to firmware variables not possible");

        return EXIT_SUCCESS;
}
