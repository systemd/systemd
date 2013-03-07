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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/mount.h>
#include <stdint.h>

#include "macro.h"
#include "smack-setup.h"
#include "util.h"
#include "log.h"
#include "label.h"

#define ACCESSES_D_PATH "/etc/smack/accesses.d/"

int smack_setup(void) {
        _cleanup_fclose_ FILE *smack = NULL;
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *entry;
        char buf[NAME_MAX];
        int dfd = -1;

        smack = fopen("/sys/fs/smackfs/load2", "we");
        if (!smack)  {
                log_info("Smack is not enabled in the kernel, not loading access rules.");
                return 0;
        }

        /* write rules to load2 from every file in the directory */
        dir = opendir(ACCESSES_D_PATH);
        if (!dir) {
                log_info("Smack access rules directory not found: " ACCESSES_D_PATH);
                return 0;
        }

        dfd = dirfd(dir);
        if (dfd < 0) {
                log_error("Smack access rules directory " ACCESSES_D_PATH " not opened: %m");
                return 0;
        }

        FOREACH_DIRENT(entry, dir, return 0) {
                _cleanup_fclose_ FILE *policy = NULL;
                _cleanup_close_ int pol = -1;

                pol = openat(dfd, entry->d_name, O_RDONLY|O_CLOEXEC);
                if (pol < 0) {
                        log_error("Smack access rule file %s not opened: %m", entry->d_name);
                        continue;
                }

                policy = fdopen(pol, "re");
                if (!policy) {
                        log_error("Smack access rule file %s not opened: %m", entry->d_name);
                        continue;
                }

                pol = -1;

                /* load2 write rules in the kernel require a line buffered stream */
                FOREACH_LINE(buf, policy, log_error("Failed to read from Smack access rule file %s: %m", entry->d_name)) {
                        fputs(buf, smack);
                        fflush(smack);
                }
        }

        log_info("Successfully loaded Smack policies.");

        return 0;
}
