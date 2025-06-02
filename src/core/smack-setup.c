/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation
  Authors:
        Nathaniel Chen <nathaniel.chen@intel.com>
***/

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "smack-setup.h"
#include "string-util.h"

#if ENABLE_SMACK

static int fdopen_unlocked_at(int dfd, const char *dir, const char *name, int *status, FILE **ret_file) {
        int fd, r;
        FILE *f;

        fd = openat(dfd, name, O_RDONLY|O_CLOEXEC);
        if (fd < 0) {
                if (*status == 0)
                        *status = -errno;

                return log_warning_errno(errno, "Failed to open \"%s/%s\": %m", dir, name);
        }

        r = fdopen_unlocked(fd, "r", &f);
        if (r < 0) {
                if (*status == 0)
                        *status = r;

                safe_close(fd);
                return log_error_errno(r, "Failed to open \"%s/%s\": %m", dir, name);
        }

        *ret_file = f;
        return 0;
}

static int write_access2_rules(const char *srcdir) {
        _cleanup_close_ int load2_fd = -EBADF, change_fd = -EBADF;
        _cleanup_closedir_ DIR *dir = NULL;
        int dfd, r;

        load2_fd = r = RET_NERRNO(open("/sys/fs/smackfs/load2", O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY));
        if (r < 0)  {
                if (r != -ENOENT)
                        log_warning_errno(r, "Failed to open %s: %m", "/sys/fs/smackfs/load2");
                return r;
        }

        change_fd = r = RET_NERRNO(open("/sys/fs/smackfs/change-rule", O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY));
        if (r < 0)  {
                if (r != -ENOENT)
                        log_warning_errno(r, "Failed to open %s: %m", "/sys/fs/smackfs/change-rule");
                return r;
        }

        /* write rules to load2 or change-rule from every file in the directory */
        dir = opendir(srcdir);
        if (!dir) {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open %s/: %m", srcdir);
                return errno; /* positive on purpose */
        }

        dfd = dirfd(dir);
        assert(dfd >= 0);

        r = 0;
        FOREACH_DIRENT(entry, dir, return 0) {
                _cleanup_fclose_ FILE *policy = NULL;

                if (!dirent_is_file(entry))
                        continue;

                if (fdopen_unlocked_at(dfd, srcdir, entry->d_name, &r, &policy) < 0)
                        continue;

                /* load2 write rules in the kernel require a line buffered stream */
                for (;;) {
                        _cleanup_free_ char *buf = NULL, *sbj = NULL, *obj = NULL, *acc1 = NULL, *acc2 = NULL;
                        int q;

                        q = read_line(policy, NAME_MAX, &buf);
                        if (q < 0)
                                return log_error_errno(q, "%s/%s: failed to read line: %m", srcdir, entry->d_name);
                        if (q == 0)
                                break;

                        if (isempty(buf) || strchr(COMMENTS, buf[0]))
                                continue;

                        /* if 3 args -> load rule   : subject object access1 */
                        /* if 4 args -> change rule : subject object access1 access2 */
                        if (sscanf(buf, "%ms %ms %ms %ms", &sbj, &obj, &acc1, &acc2) < 3) {
                                log_error_errno(errno, "%s/%s: failed to parse rule '%s', ignoring.",
                                                srcdir, entry->d_name, buf);
                                continue;
                        }

                        q = RET_NERRNO(write(isempty(acc2) ? load2_fd : change_fd, buf, strlen(buf)));
                        if (q < 0) {
                                log_error_errno(q, "%s/%s: failed to write '%s' to '%s': %m",
                                                srcdir, entry->d_name,
                                                buf, isempty(acc2) ? "/sys/fs/smackfs/load2" : "/sys/fs/smackfs/change-rule");
                                RET_GATHER(r, q);
                        }
                }
        }

        return r;
}

static int write_cipso2_rules(const char *srcdir) {
        _cleanup_close_ int cipso2_fd = -EBADF;
        _cleanup_closedir_ DIR *dir = NULL;
        int dfd, r;

        cipso2_fd = r = RET_NERRNO(open("/sys/fs/smackfs/cipso2", O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY));
        if (r < 0)  {
                if (r != -ENOENT)
                        log_warning_errno(r, "Failed to open %s: %m", "/sys/fs/smackfs/cipso2");
                return r;
        }

        /* write rules to cipso2 from every file in the directory */
        dir = opendir(srcdir);
        if (!dir) {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open %s/: %m", srcdir);
                return errno; /* positive on purpose */
        }

        dfd = dirfd(dir);
        assert(dfd >= 0);

        r = 0;
        FOREACH_DIRENT(entry, dir, return 0) {
                _cleanup_fclose_ FILE *policy = NULL;

                if (!dirent_is_file(entry))
                        continue;

                if (fdopen_unlocked_at(dfd, srcdir, entry->d_name, &r, &policy) < 0)
                        continue;

                /* cipso2 write rules in the kernel require a line buffered stream */
                for (;;) {
                        _cleanup_free_ char *buf = NULL;
                        int q;

                        q = read_line(policy, NAME_MAX, &buf);
                        if (q < 0)
                                return log_error_errno(q, "%s/%s: failed to read line: %m",
                                                       srcdir, entry->d_name);
                        if (q == 0)
                                break;

                        if (isempty(buf) || strchr(COMMENTS, buf[0]))
                                continue;

                        q = RET_NERRNO(write(cipso2_fd, buf, strlen(buf)));
                        if (q < 0) {
                                log_error_errno(q, "%s/%s: failed to write '%s' to %s: %m",
                                                srcdir, entry->d_name,
                                                buf, "/sys/fs/smackfs/cipso2");
                                RET_GATHER(r, q);
                                break;
                        }
                }
        }

        return r;
}

static int write_netlabel_rules(const char *srcdir) {
        _cleanup_fclose_ FILE *dst = NULL;
        _cleanup_closedir_ DIR *dir = NULL;
        int dfd, r;

        dst = fopen("/sys/fs/smackfs/netlabel", "we");
        if (!dst)  {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open %s/: %m", "/sys/fs/smackfs/netlabel");
                return -errno; /* negative error */
        }

        /* write rules to dst from every file in the directory */
        dir = opendir(srcdir);
        if (!dir) {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open %s/: %m", srcdir);
                return errno; /* positive on purpose */
        }

        dfd = dirfd(dir);
        assert(dfd >= 0);

        r = 0;
        FOREACH_DIRENT(entry, dir, return 0) {
                _cleanup_fclose_ FILE *policy = NULL;

                if (fdopen_unlocked_at(dfd, srcdir, entry->d_name, &r, &policy) < 0)
                        continue;

                /* load2 write rules in the kernel require a line buffered stream */
                for (;;) {
                        _cleanup_free_ char *buf = NULL;
                        int q;

                        q = read_line(policy, NAME_MAX, &buf);
                        if (q < 0)
                                return log_error_errno(q, "%s/%s: failed to read line: %m",
                                                       srcdir, entry->d_name);
                        if (q == 0)
                                break;

                        if (!fputs(buf, dst)) {
                                log_error_errno(errno, "Failed to write line to %s: %m", "/sys/fs/smackfs/netlabel");
                                RET_GATHER(r, -errno);
                                break;
                        }
                        q = fflush_and_check(dst);
                        if (q < 0) {
                                log_error_errno(q, "Failed to flush %s: %m", "/sys/fs/smackfs/netlabel");
                                RET_GATHER(r, q);
                                break;
                        }
                }
        }

        return r;
}

static int write_onlycap_list(void) {
        _cleanup_close_ int onlycap_fd = -EBADF;
        _cleanup_free_ char *list = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        size_t len = 0;
        int r;

        f = fopen("/etc/smack/onlycap", "re");
        if (!f) {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open %s: %m", "/etc/smack/onlycap");

                return errno == ENOENT ? ENOENT : -errno;
        }

        for (;;) {
                _cleanup_free_ char *buf = NULL;
                size_t l;

                r = read_line(f, LONG_LINE_MAX, &buf);
                if (r < 0)
                        return log_error_errno(r, "%s: failed to read line: %m", "/etc/smack/onlycap");
                if (r == 0)
                        break;

                if (isempty(buf) || strchr(COMMENTS, *buf))
                        continue;

                l = strlen(buf);
                if (!GREEDY_REALLOC(list, len + l + 1))
                        return log_oom();

                stpcpy(list + len, buf)[0] = ' ';
                len += l + 1;
        }

        if (len == 0)
                return 0;

        list[len - 1] = 0;

        onlycap_fd = r = RET_NERRNO(open("/sys/fs/smackfs/onlycap", O_WRONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY));
        if (r < 0) {
                if (r != -ENOENT)
                        log_warning_errno(r, "Failed to open %s: %m", "/sys/fs/smackfs/onlycap");
                return r;
        }

        r = RET_NERRNO(write(onlycap_fd, list, len));
        if (r < 0)
                return log_error_errno(r, "%s: failed to write onlycap list(%s): %m",
                                       "/sys/fs/smackfs/onlycap", list);

        return 0;
}

#endif

int mac_smack_setup(bool *loaded_policy) {

#if ENABLE_SMACK
        int r;

        assert(loaded_policy);

        r = write_access2_rules("/etc/smack/accesses.d");
        switch (r) {
        case -ENOENT:
                log_debug("Smack is not enabled in the kernel.");
                return 0;
        case ENOENT:
                log_debug("Smack access rules directory '/etc/smack/accesses.d/' not found");
                return 0;
        case 0:
                log_info("Successfully loaded Smack policies.");
                break;
        default:
                log_warning_errno(r, "Failed to load Smack access rules, ignoring: %m");
                return 0;
        }

#if HAVE_SMACK_RUN_LABEL
        r = write_string_file("/proc/self/attr/current", SMACK_RUN_LABEL, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                log_warning_errno(r, "Failed to set SMACK label \"" SMACK_RUN_LABEL "\" on self: %m");
        r = write_string_file("/sys/fs/smackfs/ambient", SMACK_RUN_LABEL, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                log_warning_errno(r, "Failed to set SMACK ambient label \"" SMACK_RUN_LABEL "\": %m");
        r = write_string_file("/sys/fs/smackfs/netlabel",
                              "0.0.0.0/0 " SMACK_RUN_LABEL, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                log_warning_errno(r, "Failed to set SMACK netlabel rule \"0.0.0.0/0 " SMACK_RUN_LABEL "\": %m");
        r = write_string_file("/sys/fs/smackfs/netlabel", "127.0.0.1 -CIPSO", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                log_warning_errno(r, "Failed to set SMACK netlabel rule \"127.0.0.1 -CIPSO\": %m");
#endif

        r = write_cipso2_rules("/etc/smack/cipso.d");
        switch (r) {
        case -ENOENT:
                log_debug("Smack/CIPSO is not enabled in the kernel.");
                return 0;
        case ENOENT:
                log_debug("Smack/CIPSO access rules directory '/etc/smack/cipso.d/' not found");
                break;
        case 0:
                log_info("Successfully loaded Smack/CIPSO policies.");
                break;
        default:
                log_warning_errno(r, "Failed to load Smack/CIPSO access rules, ignoring: %m");
        }

        r = write_netlabel_rules("/etc/smack/netlabel.d");
        switch (r) {
        case -ENOENT:
                log_debug("Smack/CIPSO is not enabled in the kernel.");
                return 0;
        case ENOENT:
                log_debug("Smack network host rules directory '/etc/smack/netlabel.d/' not found");
                break;
        case 0:
                log_info("Successfully loaded Smack network host rules.");
                break;
        default:
                log_warning_errno(r, "Failed to load Smack network host rules: %m, ignoring.");
        }

        r = write_onlycap_list();
        switch (r) {
        case -ENOENT:
                log_debug("Smack is not enabled in the kernel.");
                break;
        case ENOENT:
                log_debug("Smack onlycap list file '/etc/smack/onlycap' not found");
                break;
        case 0:
                log_info("Successfully wrote Smack onlycap list.");
                break;
        default:
                return log_struct_errno(LOG_EMERG, r,
                                        LOG_MESSAGE("Failed to write Smack onlycap list: %m"),
                                        LOG_MESSAGE_ID(SD_MESSAGE_SMACK_FAILED_WRITE_STR));
        }

        *loaded_policy = true;

#endif

        return 0;
}
