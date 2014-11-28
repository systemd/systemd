/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering
  Copyright 2013 Kay Sievers

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "util.h"
#include "log.h"
#include "boot-timestamps.h"
#include "efivars.h"
#include "acpi-fpdt.h"

static int test_acpi_fpdt(void) {
        usec_t loader_start;
        usec_t loader_exit;
        char ts_start[FORMAT_TIMESPAN_MAX];
        char ts_exit[FORMAT_TIMESPAN_MAX];
        char ts_span[FORMAT_TIMESPAN_MAX];
        int r;

        r = acpi_get_boot_usec(&loader_start, &loader_exit);
        if (r < 0) {
                if (r != -ENOENT)
                        log_error_errno(r, "Failed to read ACPI FPDT: %m");
                return r;
        }

        log_info("ACPI FPDT: loader start=%s exit=%s duration=%s",
                 format_timespan(ts_start, sizeof(ts_start), loader_start, USEC_PER_MSEC),
                 format_timespan(ts_exit, sizeof(ts_exit), loader_exit, USEC_PER_MSEC),
                 format_timespan(ts_span, sizeof(ts_span), loader_exit - loader_start, USEC_PER_MSEC));

        return 0;
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
                if (r != -ENOENT)
                        log_error_errno(r, "Failed to read EFI loader data: %m");
                return r;
        }

        log_info("EFI Loader: start=%s exit=%s duration=%s",
                 format_timespan(ts_start, sizeof(ts_start), loader_start, USEC_PER_MSEC),
                 format_timespan(ts_exit, sizeof(ts_exit), loader_exit, USEC_PER_MSEC),
                 format_timespan(ts_span, sizeof(ts_span), loader_exit - loader_start, USEC_PER_MSEC));

        return 0;
}

int main(int argc, char* argv[]) {
        char s[MAX(FORMAT_TIMESPAN_MAX, FORMAT_TIMESTAMP_MAX)];
        int r;
        dual_timestamp fw, l, k;

        test_acpi_fpdt();
        test_efi_loader();

        dual_timestamp_from_monotonic(&k, 0);

        r = boot_timestamps(NULL, &fw, &l);
        if (r < 0) {
                log_error_errno(r, "Failed to read variables: %m");
                return 1;
        }

        log_info("Firmware began %s before kernel.", format_timespan(s, sizeof(s), fw.monotonic, 0));
        log_info("Loader began %s before kernel.", format_timespan(s, sizeof(s), l.monotonic, 0));
        log_info("Firmware began %s.", format_timestamp(s, sizeof(s), fw.realtime));
        log_info("Loader began %s.", format_timestamp(s, sizeof(s), l.realtime));
        log_info("Kernel began %s.", format_timestamp(s, sizeof(s), k.realtime));

        return 0;
}
