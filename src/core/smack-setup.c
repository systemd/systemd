/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2013 Intel Corporation
  Authors:
        Nathaniel Chen <nathaniel.chen@intel.com>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2.1 of the License,
  or (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "smack-setup.h"
#include "string-util.h"
#include "util.h"

#ifdef HAVE_SMACK

static int write_access2_rules(const char* srcdir) {
        _cleanup_close_ int load2_fd = -1, change_fd = -1;
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *entry;
        char buf[NAME_MAX];
        int dfd = -1;
        int r = 0;

        load2_fd = open("/sys/fs/smackfs/load2", O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (load2_fd < 0)  {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open '/sys/fs/smackfs/load2': %m");
                return -errno; /* negative error */
        }

        change_fd = open("/sys/fs/smackfs/change-rule", O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (change_fd < 0)  {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open '/sys/fs/smackfs/change-rule': %m");
                return -errno; /* negative error */
        }

        /* write rules to load2 or change-rule from every file in the directory */
        dir = opendir(srcdir);
        if (!dir) {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to opendir '%s': %m", srcdir);
                return errno; /* positive on purpose */
        }

        dfd = dirfd(dir);
        assert(dfd >= 0);

        FOREACH_DIRENT(entry, dir, return 0) {
                int fd;
                _cleanup_fclose_ FILE *policy = NULL;

                if (!dirent_is_file(entry))
                        continue;

                fd = openat(dfd, entry->d_name, O_RDONLY|O_CLOEXEC);
                if (fd < 0) {
                        if (r == 0)
                                r = -errno;
                        log_warning_errno(errno, "Failed to open '%s': %m", entry->d_name);
                        continue;
                }

                policy = fdopen(fd, "re");
                if (!policy) {
                        if (r == 0)
                                r = -errno;
                        safe_close(fd);
                        log_error_errno(errno, "Failed to open '%s': %m", entry->d_name);
                        continue;
                }

                /* load2 write rules in the kernel require a line buffered stream */
                FOREACH_LINE(buf, policy,
                             log_error_errno(errno, "Failed to read line from '%s': %m",
                                             entry->d_name)) {

                        _cleanup_free_ char *sbj = NULL, *obj = NULL, *acc1 = NULL, *acc2 = NULL;

                        if (isempty(truncate_nl(buf)))
                                continue;

                        /* if 3 args -> load rule   : subject object access1 */
                        /* if 4 args -> change rule : subject object access1 access2 */
                        if (sscanf(buf, "%ms %ms %ms %ms", &sbj, &obj, &acc1, &acc2) < 3) {
                                log_error_errno(errno, "Failed to parse rule '%s' in '%s', ignoring.", buf, entry->d_name);
                                continue;
                        }

                        if (write(isempty(acc2) ? load2_fd : change_fd, buf, strlen(buf)) < 0) {
                                if (r == 0)
                                        r = -errno;
                                log_error_errno(errno, "Failed to write '%s' to '%s' in '%s'",
                                                buf, isempty(acc2) ? "/sys/fs/smackfs/load2" : "/sys/fs/smackfs/change-rule", entry->d_name);
                        }
                }
        }

        return r;
}

static int write_cipso2_rules(const char* srcdir) {
        _cleanup_close_ int cipso2_fd = -1;
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *entry;
        char buf[NAME_MAX];
        int dfd = -1;
        int r = 0;

        cipso2_fd = open("/sys/fs/smackfs/cipso2", O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (cipso2_fd < 0)  {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to open '/sys/fs/smackfs/cipso2': %m");
                return -errno; /* negative error */
        }

        /* write rules to cipso2 from every file in the directory */
        dir = opendir(srcdir);
        if (!dir) {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to opendir '%s': %m", srcdir);
                return errno; /* positive on purpose */
        }

        dfd = dirfd(dir);
        assert(dfd >= 0);

        FOREACH_DIRENT(entry, dir, return 0) {
                int fd;
                _cleanup_fclose_ FILE *policy = NULL;

                if (!dirent_is_file(entry))
                        continue;

                fd = openat(dfd, entry->d_name, O_RDONLY|O_CLOEXEC);
                if (fd < 0) {
                        if (r == 0)
                                r = -errno;
                        log_error_errno(errno, "Failed to open '%s': %m", entry->d_name);
                        continue;
                }

                policy = fdopen(fd, "re");
                if (!policy) {
                        if (r == 0)
                                r = -errno;
                        safe_close(fd);
                        log_error_errno(errno, "Failed to open '%s': %m", entry->d_name);
                        continue;
                }

                /* cipso2 write rules in the kernel require a line buffered stream */
                FOREACH_LINE(buf, policy,
                             log_error_errno(errno, "Failed to read line from '%s': %m",
                                             entry->d_name)) {

                        if (isempty(truncate_nl(buf)))
                                continue;

                        if (write(cipso2_fd, buf, strlen(buf)) < 0) {
                                if (r == 0)
                                        r = -errno;
                                log_error_errno(errno, "Failed to write '%s' to '/sys/fs/smackfs/cipso2' in '%s'",
                                                buf, entry->d_name);
                                break;
                        }
                }
        }

        return r;
}

#endif

int mac_smack_setup(bool *loaded_policy) {

#ifdef HAVE_SMACK

        int r;

        assert(loaded_policy);

        r = write_access2_rules("/etc/smack/accesses.d/");
        switch(r) {
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

#ifdef SMACK_RUN_LABEL
        r = write_string_file("/proc/self/attr/current", SMACK_RUN_LABEL, 0);
        if (r)
                log_warning_errno(r, "Failed to set SMACK label \"%s\" on self: %m", SMACK_RUN_LABEL);
#endif

        r = write_cipso2_rules("/etc/smack/cipso.d/");
        switch(r) {
        case -ENOENT:
                log_debug("Smack/CIPSO is not enabled in the kernel.");
                return 0;
        case ENOENT:
                log_debug("Smack/CIPSO access rules directory '/etc/smack/cipso.d/' not found");
                return 0;
        case 0:
                log_info("Successfully loaded Smack/CIPSO policies.");
                break;
        default:
                log_warning_errno(r, "Failed to load Smack/CIPSO access rules, ignoring: %m");
                return 0;
        }

        *loaded_policy = true;

#endif

        return 0;
}
