/* SPDX-License-Identifier: LGPL-2.1+ */

#include "acpi-fpdt.h"
#include "boot-timestamps.h"
#include "efivars.h"
#include "log.h"
#include "util.h"

static int test_acpi_fpdt(void) {
        usec_t loader_start;
        usec_t loader_exit;
        char ts_start[FORMAT_TIMESPAN_MAX];
        char ts_exit[FORMAT_TIMESPAN_MAX];
        char ts_span[FORMAT_TIMESPAN_MAX];
        int r;

        r = acpi_get_boot_usec(&loader_start, &loader_exit);
        if (r < 0) {
                bool ok = r == -ENOENT || (getuid() != 0 && r == -EACCES) || r == -ENODATA;

                log_full_errno(ok ? LOG_DEBUG : LOG_ERR,
                               r, "Failed to read ACPI FPDT: %m");
                return ok ? 0 : r;
        }

        log_info("ACPI FPDT: loader start=%s exit=%s duration=%s",
                 format_timespan(ts_start, sizeof(ts_start), loader_start, USEC_PER_MSEC),
                 format_timespan(ts_exit, sizeof(ts_exit), loader_exit, USEC_PER_MSEC),
                 format_timespan(ts_span, sizeof(ts_span), loader_exit - loader_start, USEC_PER_MSEC));
        return 1;
}

static int test_efi_loader(void) {
        usec_t loader_start;
        usec_t loader_exit;
        char ts_start[FORMAT_TIMESPAN_MAX];
        char ts_exit[FORMAT_TIMESPAN_MAX];
        char ts_span[FORMAT_TIMESPAN_MAX];
        int r;

        r = efi_loader_get_boot_usec(&loader_start, &loader_exit);
        if (r < 0) {
                bool ok = r == -ENOENT || (getuid() != 0 && r == -EACCES);

                log_full_errno(ok ? LOG_DEBUG : LOG_ERR,
                               r, "Failed to read EFI loader data: %m");
                return ok ? 0 : r;
        }

        log_info("EFI Loader: start=%s exit=%s duration=%s",
                 format_timespan(ts_start, sizeof(ts_start), loader_start, USEC_PER_MSEC),
                 format_timespan(ts_exit, sizeof(ts_exit), loader_exit, USEC_PER_MSEC),
                 format_timespan(ts_span, sizeof(ts_span), loader_exit - loader_start, USEC_PER_MSEC));
        return 1;
}

static int test_boot_timestamps(void) {
        char s[MAX(FORMAT_TIMESPAN_MAX, FORMAT_TIMESTAMP_MAX)];
        int r;
        dual_timestamp fw, l, k;

        dual_timestamp_from_monotonic(&k, 0);

        r = boot_timestamps(NULL, &fw, &l);
        if (r < 0) {
                bool ok = r == -ENOENT || (getuid() != 0 && r == -EACCES);

                log_full_errno(ok ? LOG_DEBUG : LOG_ERR,
                               r, "Failed to read variables: %m");
                return ok ? 0 : r;
        }

        log_info("Firmware began %s before kernel.", format_timespan(s, sizeof(s), fw.monotonic, 0));
        log_info("Loader began %s before kernel.", format_timespan(s, sizeof(s), l.monotonic, 0));
        log_info("Firmware began %s.", format_timestamp(s, sizeof(s), fw.realtime));
        log_info("Loader began %s.", format_timestamp(s, sizeof(s), l.realtime));
        log_info("Kernel began %s.", format_timestamp(s, sizeof(s), k.realtime));
        return 1;
}

int main(int argc, char* argv[]) {
        int p, q, r;

        log_set_max_level(LOG_DEBUG);
        log_parse_environment();

        p = test_acpi_fpdt();
        assert(p >= 0);
        q = test_efi_loader();
        assert(q >= 0);
        r = test_boot_timestamps();
        assert(r >= 0);

        bool any = p > 0 || q > 0 || r > 0;
        if (!any)
                log_notice("%s: access to firmware variable not possible, skipping tests.",
                           program_invocation_short_name);

        return any ? EXIT_SUCCESS : EXIT_TEST_SKIP;
}
