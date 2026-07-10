/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/file.h>
#include <unistd.h>
#include "sd-json.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "log.h"
#include "measurement-log.h"
#include "mkdir.h"
#include "stat-util.h"
#include "sync-util.h"

int measurement_log_open(const char *path) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        (void) mkdir_parents(path, 0755);

        /* We use access mode 0600 here (even though the measurements should not strictly be confidential),
         * because we use BSD file locking on it, and if anyone but root can access the file they can also
         * lock it, which we want to avoid. */
        fd = open(path, O_CREAT|O_WRONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW, 0600);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open measurement log file '%s' for writing, ignoring: %m", path);

        if (flock(fd, LOCK_EX) < 0)
                return log_debug_errno(errno, "Failed to lock measurement log file '%s', ignoring: %m", path);

        r = fd_verify_regular(fd);
        if (r < 0)
                return log_debug_errno(r, "Measurement log file '%s' is not regular, ignoring: %m", path);

        return TAKE_FD(fd);
}

int measurement_log_dirty(int fd) {
        struct stat st;

        if (fd < 0) /* Apparently measurement_log_open() failed earlier, let's not complain again */
                return 0;

        /* We set the sticky bit when we are about to append to the log file. We'll unset it afterwards
         * again. If we manage to take a lock on a file that has it set we know we didn't write it fully and
         * it is corrupted. We return -ESTALE then; callers shall not reset the marker when they are done,
         * so that the incompleteness remains detectable. Ideally we'd like to use user xattrs for this, but
         * unfortunately tmpfs (which is our assumed backend fs) doesn't know user xattrs. */

        if (fstat(fd, &st) < 0)
                return log_debug_errno(errno, "Failed to fstat measurement log file, ignoring: %m");

        if (st.st_mode & S_ISVTX)
                return log_debug_errno(SYNTHETIC_ERRNO(ESTALE), "measurement log file aborted, ignoring.");

        if (fchmod(fd, 0600 | S_ISVTX) < 0)
                return log_debug_errno(errno, "Failed to chmod() measurement log file, ignoring: %m");

        return 0;
}

int measurement_log_clean(int fd, bool reset_marker) {
        int r;

        if (fd < 0) /* Apparently measurement_log_open() failed earlier, let's not complain again */
                return 0;

        if (fsync(fd) < 0)
                return log_debug_errno(errno, "Failed to sync JSON data: %m");

        /* If the dirty marker was already set when we acquired the log, an earlier writer died before
         * writing its record, i.e. the log is missing a record. Keep the marker then, so that the
         * incompleteness remains detectable. */
        if (!reset_marker)
                return 0;

        /* Unset S_ISVTX again */
        if (fchmod(fd, 0600) < 0)
                return log_debug_errno(errno, "Failed to chmod() measurement log file, ignoring: %m");

        r = fsync_full(fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to sync JSON log: %m");

        return 0;
}

int measurement_log_append(int fd, sd_json_variant *record, bool reset_marker) {
        _cleanup_free_ char *f = NULL;
        int r;

        /* The log implements a subset of the TCG Canonical Event Log Format – the JSON flavour –
         * (https://trustedcomputinggroup.org/resource/canonical-event-log-format/), but departs in certain
         * ways from it, specifically:
         *
         * - We don't write out a recnum. It's a bit too vaguely defined which means we'd have to read
         *   through the whole logs (include firmware logs) before knowing what the next value is we should
         *   use. Hence we simply don't write this out as append-time, and instead expect a consumer to add
         *   it in when it uses the data.
         *
         * - We write this out in RFC 7464 application/json-seq rather than as a JSON array. Writing this as
         *   JSON array would mean that for each appending we'd have to read the whole log file fully into
         *   memory before writing it out again. We prefer a strictly append-only write pattern however. (RFC
         *   7464 is what jq --seq eats.) Conversion into a proper JSON array is trivial.
         *
         * It should be possible to convert this format in a relatively straight-forward way into the
         * official TCG Canonical Event Log Format on read, by simply adding in a few more fields that can be
         * determined from the full dataset.
         */

        if (fd < 0) /* Apparently measurement_log_open() failed earlier, let's not complain again */
                return 0;

        r = sd_json_variant_format(record, SD_JSON_FORMAT_SEQ, &f);
        if (r < 0)
                return log_debug_errno(r, "Failed to format JSON: %m");

        if (lseek(fd, 0, SEEK_END) < 0)
                return log_debug_errno(errno, "Failed to seek to end of JSON log: %m");

        r = loop_write(fd, f, SIZE_MAX);
        if (r < 0)
                return log_debug_errno(r, "Failed to write JSON data to log: %m");

        r = measurement_log_clean(fd, reset_marker);
        if (r < 0)
                return r;

        return 1;
}
