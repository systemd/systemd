/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>

#include "macro.h"
#include "path-util.h"

bool dirent_is_file(const struct dirent *de) _pure_;
bool dirent_is_file_with_suffix(const struct dirent *de, const char *suffix) _pure_;
int dirent_ensure_type(int dir_fd, struct dirent *de);

struct dirent *readdir_ensure_type(DIR *d);
struct dirent *readdir_no_dot(DIR *dirp);

#define FOREACH_DIRENT_ALL(de, d, on_error)                             \
        for (struct dirent *(de) = readdir_ensure_type(d);; (de) = readdir_ensure_type(d)) \
                if (!de) {                                              \
                        if (errno > 0) {                                \
                                on_error;                               \
                        }                                               \
                        break;                                          \
                } else

#define FOREACH_DIRENT(de, d, on_error)                                 \
        FOREACH_DIRENT_ALL(de, d, on_error)                             \
             if (hidden_or_backup_file((de)->d_name))                   \
                     continue;                                          \
             else

/* Maximum space one dirent structure might require at most */
#define DIRENT_SIZE_MAX CONST_MAX(sizeof(struct dirent), offsetof(struct dirent, d_name) + NAME_MAX + 1)

/* Only if 64bit off_t is enabled struct dirent + struct dirent64 are actually the same. We require this, and
 * we want them to be interchangeable to make getdents64() work, hence verify that. */
assert_cc(_FILE_OFFSET_BITS == 64);

#define FOREACH_DIRENT_IN_BUFFER(de, buf, sz)                           \
        for (void *_end = (uint8_t*) ({ (de) = (buf); }) + (sz);        \
             (uint8_t*) (de) < (uint8_t*) _end;                         \
             (de) = (struct dirent*) ((uint8_t*) (de) + (de)->d_reclen))

#define DEFINE_DIRENT_BUFFER(name, sz)                                  \
        union {                                                         \
                struct dirent de;                                       \
                uint8_t data[(sz) * DIRENT_SIZE_MAX];                   \
        } name
