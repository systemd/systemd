/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright (C) 2012 Roberto Sassu - Politecnico di Torino, Italy
                                     TORSEC group -- http://security.polito.it

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

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "ima-setup.h"
#include "mount-setup.h"
#include "macro.h"
#include "util.h"
#include "log.h"
#include "label.h"

#define IMA_SECFS_DIR "/sys/kernel/security/ima"
#define IMA_SECFS_POLICY IMA_SECFS_DIR "/policy"
#define IMA_POLICY_PATH "/etc/ima/ima-policy"

int ima_setup(void) {

#ifdef HAVE_IMA
        struct stat st;
        ssize_t policy_size = 0, written = 0;
        char *policy;
        _cleanup_close_ int policyfd = -1, imafd = -1;
        int result = 0;

        if (stat(IMA_POLICY_PATH, &st) < 0)
                return 0;

        policy_size = st.st_size;
        if (stat(IMA_SECFS_DIR, &st) < 0) {
                log_debug("IMA support is disabled in the kernel, ignoring.");
                return 0;
        }

        if (stat(IMA_SECFS_POLICY, &st) < 0) {
                log_error("Another IMA custom policy has already been loaded, "
                          "ignoring.");
                return 0;
        }

        policyfd = open(IMA_POLICY_PATH, O_RDONLY|O_CLOEXEC);
        if (policyfd < 0) {
                log_error("Failed to open the IMA custom policy file %s (%m), "
                          "ignoring.", IMA_POLICY_PATH);
                return 0;
        }

        imafd = open(IMA_SECFS_POLICY, O_WRONLY|O_CLOEXEC);
        if (imafd < 0) {
                log_error("Failed to open the IMA kernel interface %s (%m), "
                          "ignoring.", IMA_SECFS_POLICY);
                goto out;
        }

        policy = mmap(NULL, policy_size, PROT_READ, MAP_PRIVATE, policyfd, 0);
        if (policy == MAP_FAILED) {
                log_error("mmap() failed (%m), freezing");
                result = -errno;
                goto out;
        }

        written = loop_write(imafd, policy, (size_t)policy_size, false);
        if (written != policy_size) {
                log_error("Failed to load the IMA custom policy file %s (%m), "
                          "ignoring.", IMA_POLICY_PATH);
                goto out_mmap;
        }

        log_info("Successfully loaded the IMA custom policy %s.",
                 IMA_POLICY_PATH);
out_mmap:
        munmap(policy, policy_size);
out:
        if (result)
                 return result;
#endif /* HAVE_IMA */

        return 0;
}
