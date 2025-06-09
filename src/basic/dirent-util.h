/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>     /* IWYU pragma: export */

#include "forward.h"
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

/* Musl provides posix_getdents(). But glibc does not, and provides their own implementation as getdents64().
 * Let's introduce a simple wrapper. */
#if !HAVE_POSIX_GETDENTS
static inline ssize_t posix_getdents(int fd, void *buf, size_t nbyte, int flags) {
        assert(fd >= 0);
        assert(buf);
        assert(nbyte > 0);

        if (flags != 0)
                return -EINVAL; /* Currently flags must be zero. */

#if HAVE_STRUCT_DIRENT64
        return getdents64(fd, buf, nbyte);
#else
        return getdents(fd, buf, nbyte);
#endif
}
#endif

/* Maximum space one dirent structure might require at most */
#define DIRENT_SIZE_MAX CONST_MAX(sizeof(struct dirent), offsetof(struct dirent, d_name) + NAME_MAX + 1)

/* Only if 64-bit off_t is enabled struct dirent + struct dirent64 are actually the same. We require this, and
 * we want them to be interchangeable to make posix_getdents() work, hence verify that. */
assert_cc(_FILE_OFFSET_BITS == 64);
/* These asserts would fail on musl where the LFS extensions don't exist. They should
 * always be present on glibc however. */
#if HAVE_STRUCT_DIRENT64
assert_cc(sizeof(struct dirent) == sizeof(struct dirent64));
assert_cc(offsetof(struct dirent, d_ino) == offsetof(struct dirent64, d_ino));
assert_cc(sizeof_field(struct dirent, d_ino) == sizeof_field(struct dirent64, d_ino));
assert_cc(offsetof(struct dirent, d_off) == offsetof(struct dirent64, d_off));
assert_cc(sizeof_field(struct dirent, d_off) == sizeof_field(struct dirent64, d_off));
assert_cc(offsetof(struct dirent, d_reclen) == offsetof(struct dirent64, d_reclen));
assert_cc(sizeof_field(struct dirent, d_reclen) == sizeof_field(struct dirent64, d_reclen));
assert_cc(offsetof(struct dirent, d_type) == offsetof(struct dirent64, d_type));
assert_cc(sizeof_field(struct dirent, d_type) == sizeof_field(struct dirent64, d_type));
assert_cc(offsetof(struct dirent, d_name) == offsetof(struct dirent64, d_name));
assert_cc(sizeof_field(struct dirent, d_name) == sizeof_field(struct dirent64, d_name));
#endif

#define FOREACH_DIRENT_IN_BUFFER(de, buf, sz)                           \
        for (void *_end = (uint8_t*) ({ (de) = (buf); }) + (sz);        \
             (uint8_t*) (de) < (uint8_t*) _end;                         \
             (de) = (struct dirent*) ((uint8_t*) (de) + (de)->d_reclen))

#define DEFINE_DIRENT_BUFFER(name, sz)                                  \
        union {                                                         \
                struct dirent de;                                       \
                uint8_t data[(sz) * DIRENT_SIZE_MAX];                   \
        } name
