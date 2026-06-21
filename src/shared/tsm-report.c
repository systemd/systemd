/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "iovec-util.h"
#include "log.h"
#include "parse-util.h"
#include "process-util.h"
#include "tsm-report.h"

#define TSM_REPORT_PATH "/sys/kernel/config/tsm/report"
#define TSM_INBLOB_MAX 64U

#define FORMAT_PRIVLEVEL(privlevel) \
        snprintf_ok((char[DECIMAL_STR_MAX(unsigned)]){}, DECIMAL_STR_MAX(unsigned), "%u", (privlevel))

TsmReport *tsm_report_free(TsmReport *report) {
        if (!report)
                return NULL;

        free(report->provider);
        iovec_done(&report->outblob);
        iovec_done(&report->auxblob);
        iovec_done(&report->manifestblob);

        return mfree(report);
}

int tsm_report_supported(void) {
        if (access(TSM_REPORT_PATH, F_OK) < 0) {
                if (errno != ENOENT)
                        return log_debug_errno(errno, "Failed to check for " TSM_REPORT_PATH ": %m");

                return false;  /* configfs not mounted, or tsm module not loaded */
        }
        return true;
}

static int tsm_report_fill(
                int entry_fd,
                const struct iovec *report_data,
                const TsmReportOptions *options,
                TsmReport **ret) {

        _cleanup_close_ int inblob_fd = -EBADF;
        _cleanup_(tsm_report_freep) TsmReport *report = NULL;
        _cleanup_free_ char *floor = NULL;
        bool has_privlevel = false, has_floor = false;
        unsigned privlevel = 0, privlevel_floor = 0;
        int r;

        assert(entry_fd >= 0);
        assert(report_data);
        assert(ret);

        r = read_one_line_file_at(entry_fd, "privlevel_floor", &floor);
        if (r >= 0) {
                r = safe_atou(floor, &privlevel_floor);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse 'privlevel_floor' attribute: %m");
                has_floor = true;
        } else if (r != -ENOENT)
                return log_debug_errno(r, "Failed to read 'privlevel_floor' attribute: %m");
        /* -ENOENT: provider has no privlevel concept, leave it unset. */

        if (options && options->privlevel_set) {
                if (!has_floor)
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "TSM provider does not support 'privlevel'.");

                if (options->privlevel < privlevel_floor)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Requested privlevel %u is below the provider's floor %u.",
                                               options->privlevel, privlevel_floor);

                privlevel = options->privlevel;
                has_privlevel = true;
        } else if (has_floor) {
                privlevel = privlevel_floor;
                has_privlevel = true;
        }

        /* Write inputs. */

        if (has_privlevel) {
                r = write_string_file_at(entry_fd, "privlevel",
                                         FORMAT_PRIVLEVEL(privlevel),
                                         WRITE_STRING_FILE_DISABLE_BUFFER);
                if (r < 0)
                        return log_debug_errno(r, "Failed to write 'privlevel' attribute: %m");
        }

        /* inblob must be exactly 64 bytes, pad with zeros. */
        uint8_t inblob[TSM_INBLOB_MAX] = {};
        memcpy(inblob, report_data->iov_base, report_data->iov_len);

        inblob_fd = openat(entry_fd, "inblob", O_WRONLY|O_CLOEXEC);
        if (inblob_fd < 0)
                return log_debug_errno(errno, "Failed to open 'inblob' attribute: %m");
        r = loop_write(inblob_fd, inblob, sizeof(inblob));
        if (r < 0)
                return log_debug_errno(r, "Failed to write 'inblob' attribute: %m");
        inblob_fd = safe_close(inblob_fd);  /* configfs commits the buffered write only on close. */

        /* Read output. */

        report = new0(TsmReport, 1);
        if (!report)
                return log_oom_debug();

        r = read_full_file_at(entry_fd, "outblob",
                              (char**) &report->outblob.iov_base, &report->outblob.iov_len);
        if (r < 0)
                return log_debug_errno(r, "Failed to read 'outblob' attribute: %m");

        r = read_one_line_file_at(entry_fd, "provider", &report->provider);
        if (r < 0)
                return log_debug_errno(r, "Failed to read 'provider' attribute: %m");

        r = read_full_file_at(entry_fd, "auxblob",
                              (char**) &report->auxblob.iov_base, &report->auxblob.iov_len);
        if (r < 0 && r != -ENOENT) /* auxblob is optional */
                return log_debug_errno(r, "Failed to read 'auxblob' attribute: %m");

        r = read_full_file_at(entry_fd, "manifestblob",
                              (char**) &report->manifestblob.iov_base, &report->manifestblob.iov_len);
        if (r < 0 && r != -ENOENT) /* manifestblob is optional */
                return log_debug_errno(r, "Failed to read 'manifestblob' attribute: %m");

        *ret = TAKE_PTR(report);
        return 0;
}

int tsm_report_acquire(
                const struct iovec *report_data,
                const TsmReportOptions *options,
                TsmReport **ret) {

        _cleanup_close_ int report_fd = -EBADF, entry_fd = -EBADF;
        _cleanup_free_ char *name = NULL;
        sd_id128_t rnd;
        int r;

        assert(ret);

        if (!report_data || !iovec_is_set(report_data))
                return -EINVAL;
        if (report_data->iov_len > TSM_INBLOB_MAX)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Report data too large (%zu bytes, max %u)",
                                       report_data->iov_len, TSM_INBLOB_MAX);

        report_fd = open(TSM_REPORT_PATH, O_DIRECTORY|O_CLOEXEC|O_RDONLY);
        if (report_fd < 0) {
                if (errno == ENOENT)
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "configfs-tsm interface not available at " TSM_REPORT_PATH ".");
                return log_debug_errno(errno, "Failed to open " TSM_REPORT_PATH ": %m");
        }

        /* Private, unique entry name so we don't race with other callers.
         * PID is included for attribution. */
        r = sd_id128_randomize(&rnd);
        if (r < 0)
                return log_debug_errno(r, "Failed to generate report entry name: %m");
        r = asprintf(&name, "systemd-report-" PID_FMT "-%s", getpid_cached(), SD_ID128_TO_STRING(rnd));
        if (r < 0)
                return log_oom_debug();

        entry_fd = open_mkdir_at(report_fd, name, O_EXCL|O_RDONLY|O_CLOEXEC, 0700);
        if (entry_fd < 0)
                return log_debug_errno(entry_fd, "Failed to create TSM report entry: %m");

        r = tsm_report_fill(entry_fd, report_data, options, ret);

        /* Remove the entry regardless of success/failure. */
        if (unlinkat(report_fd, name, AT_REMOVEDIR) < 0)
                log_debug_errno(errno, "Failed to remove TSM report entry '%s', ignoring: %m", name);

        return r;
}
