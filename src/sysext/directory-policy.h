/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef enum DirectoryPolicy {
        DIRECTORY_POLICY_NO,   /* never permit directory images */
        DIRECTORY_POLICY_YES,  /* always permit directory images */
        DIRECTORY_POLICY_AUTO, /* only permit directory images on protected or OS storage */
        _DIRECTORY_POLICY_MAX,
        _DIRECTORY_POLICY_INVALID = -EINVAL,
} DirectoryPolicy;

const char* directory_policy_to_string(DirectoryPolicy i) _const_;
DirectoryPolicy directory_policy_from_string(const char *s) _pure_;

int directory_policy_check(
                DirectoryPolicy policy,
                const char *path,
                int fd,
                const dev_t *trusted_devnums);

/* Size of the zero-terminated array acquire_trusted_file_systems() fills in: up to four file systems (/,
 * /usr/ itself and its backing file system if covered by a sysext overlayfs, /var/), plus the terminating
 * zero entry. */
#define TRUSTED_FILE_SYSTEMS_MAX 5U

int acquire_trusted_file_systems(const char *root, dev_t ret[static TRUSTED_FILE_SYSTEMS_MAX]);
