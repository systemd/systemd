/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/statvfs.h>

#include "sd-id128.h"

#include "coredump-ratelimit.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "missing_sched.h"
#include "string-util.h"
#include "time-util.h"
#include "user-util.h"
#include "xattr-util.h"

static int exe_from_file_name(const char *path, const char *file_name, char **ret) {
        _cleanup_free_ char *k = NULL;

        assert(path);
        assert(file_name);

        k = path_join(path, file_name);
        if (!k)
                return log_oom();

        /* Retrieve the executable path */
        return lgetxattr_malloc(k, "user.coredump.exe", ret);
}

static int boot_id_from_file_name(const char *path, const char *file_name, sd_id128_t **ret) {
        _cleanup_free_ char *k = NULL, *id = NULL;
        int r;

        assert(path);
        assert(file_name);

        k = path_join(path, file_name);
        if (!k)
                return log_oom();

        r = lgetxattr_malloc(k, "user.coredump.bootid", &id);
        if (r < 0)
                return r;

        /* Retrieve the boot ID */
        return sd_id128_from_string(id, *ret);
}

int coredump_ratelimit(const char *executable_path, usec_t interval, unsigned burst, unsigned max_coredumps_per_boot) {
        _cleanup_closedir_ DIR *d = NULL;
        unsigned int count = 0, perboot_count = 0;
        usec_t curr_ts;
        sd_id128_t boot_id;
        char sid[SD_ID128_STRING_MAX];
        int r;

        /* If the executable path is not given, then return -EINVAL. No rate limit happens. */
        if (!executable_path)
                return -EINVAL;

        /* Either if burst or interval is zero then rate limit is disabled */
        if ((burst == 0 || interval == 0) && max_coredumps_per_boot == 0)
                return 0; /* No rate limit */

        /* Whenever a daemon crashes, we compare the number of core dump files present in the
         * /var/lib/systemd/coredump belonging to that daemon and generated within the
         * rate limit interval with the rate limit. If the limit is reached, the core dump
         * will not be processed further for generation.
         */
        d = opendir("/var/lib/systemd/coredump");
        if (!d) {
                if (errno == ENOENT)
                        return 0; /* No core dumps */
                return log_error_errno(errno, "Can't open coredump directory: %m");
        }

        /* Get the current timestamp */
        curr_ts = now(CLOCK_REALTIME);
        log_debug("Current time = "USEC_FMT" usecs", curr_ts);
        log_debug("Rate limit interval = "USEC_FMT" usecs", interval);

        /* Known limitation:
         * If system time is changed (advanced or delayed), then it results in a new
         * rate limit window, allowing the generation of new core dumps until the limit
         * is reached again.
         */
        r = sd_id128_get_boot(&boot_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get boot ID: %m");

        sd_id128_to_string(boot_id, sid);
        log_debug("Boot ID = %s\n", sid);

        FOREACH_DIRENT_ALL(de, d, goto fail) {
                struct stat st;
                _cleanup_free_ char *exe = NULL;
                _cleanup_free_ sd_id128_t *f_boot_id = NULL;
                usec_t ts;

                r = exe_from_file_name("/var/lib/systemd/coredump", de->d_name, &exe);
                if (r < 0)
                        continue;

                /* Core file belongs to the crashing process */
                if (!streq(exe, executable_path))
                        continue;

                r = boot_id_from_file_name("/var/lib/systemd/coredump", de->d_name, &f_boot_id);
                if (r < 0)
                        continue;

                log_debug("Processing core file: %s", de->d_name);

                /* Core file is generated in the current boot */
                if (sd_id128_equal(*f_boot_id, boot_id))
                        continue;

                if (fstatat(dirfd(d), de->d_name, &st, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW) <
                        0) {
                        if (errno != ENOENT)
                                log_warning_errno(
                                                errno,
                                                "Failed to stat /var/lib/systemd/coredump/%s: %m",
                                                de->d_name);
                        continue;
                }

                if (!S_ISREG(st.st_mode))
                        continue;

                if (max_coredumps_per_boot > 0) {
                        perboot_count++;
                        if (perboot_count >= max_coredumps_per_boot)
                                return perboot_count;
                }
                ts = timespec_load(&st.st_mtim);
                /* If the core file is generated within the rate limit interval, then increment the count */
                if (interval > 0 && burst > 0 &&
                        ((ts < curr_ts) && (ts > (curr_ts - interval)))) {
                        count++;
                        /* Enable rate limiting and avoid core dump generation
                                * if the number of core dumps generated for the crashing process
                                * is greater or equal to the rate limit burst */
                        if (count >= burst)
                                return count;
                }
        }

        return 0; /* Process the coredump generation */

fail:
        return log_error_errno(errno, "Failed to read directory: %m");
}