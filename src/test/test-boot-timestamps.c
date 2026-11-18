/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "acpi-fpdt.h"
#include "boot-timestamps.h"
#include "efi-loader.h"
#include "errno-util.h"
#include "log.h"
#include "tests.h"
#include "time-util.h"

TEST(acpi_fpdt) {
        usec_t loader_start, loader_exit;
        int r;

        r = acpi_get_boot_usec(&loader_start, &loader_exit);
        if (IN_SET(r, -ENOENT, -ENODATA, -ERANGE) || ERRNO_IS_NEG_PRIVILEGE(r))
                return (void) log_tests_skipped_errno(r, "Failed to read ACPI FPDT");
        ASSERT_OK(r);

        log_info("ACPI FPDT: loader start=%s exit=%s duration=%s",
                 FORMAT_TIMESPAN(loader_start, USEC_PER_MSEC),
                 FORMAT_TIMESPAN(loader_exit, USEC_PER_MSEC),
                 FORMAT_TIMESPAN(loader_exit - loader_start, USEC_PER_MSEC));
}

TEST(efi_loader) {
        usec_t loader_start, loader_exit;
        int r;

        r = efi_loader_get_boot_usec(&loader_start, &loader_exit);
        if (IN_SET(r, -ENOENT, -EOPNOTSUPP) || ERRNO_IS_NEG_PRIVILEGE(r))
                return (void) log_tests_skipped_errno(r, "Failed to read EFI loader data");
        ASSERT_OK(r);

        log_info("EFI Loader: start=%s exit=%s duration=%s",
                 FORMAT_TIMESPAN(loader_start, USEC_PER_MSEC),
                 FORMAT_TIMESPAN(loader_exit, USEC_PER_MSEC),
                 FORMAT_TIMESPAN(loader_exit - loader_start, USEC_PER_MSEC));
}

TEST(boot_timestamps) {
        dual_timestamp fw, l, k;
        int r;

        dual_timestamp_from_monotonic(&k, 0);

        r = boot_timestamps(NULL, &fw, &l);
        if (IN_SET(r, -ENOENT, -EOPNOTSUPP) || ERRNO_IS_NEG_PRIVILEGE(r))
                return (void) log_tests_skipped_errno(r, "Failed to read variables");
        ASSERT_OK(r);

        log_info("Firmware began %s before kernel.", FORMAT_TIMESPAN(fw.monotonic, 0));
        log_info("Loader began %s before kernel.", FORMAT_TIMESPAN(l.monotonic, 0));
        log_info("Firmware began %s.", FORMAT_TIMESTAMP(fw.realtime));
        log_info("Loader began %s.", FORMAT_TIMESTAMP(l.realtime));
        log_info("Kernel began %s.", FORMAT_TIMESTAMP(k.realtime));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
