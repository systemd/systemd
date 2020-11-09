/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "cryptsetup-keyfile.h"
#include "fd-util.h"
#include "format-util.h"
#include "memory-util.h"
#include "path-util.h"
#include "stat-util.h"
#include "strv.h"

#define KEY_FILE_SIZE_MAX (16U*1024U*1024U) /* 16 MiB */

int load_key_file(
                const char *key_file,
                char **search_path,
                size_t key_file_size,
                uint64_t key_file_offset,
                void **ret_key,
                size_t *ret_key_size) {

        _cleanup_(erase_and_freep) char *buffer = NULL;
        _cleanup_free_ char *discovered_path = NULL;
        _cleanup_close_ int fd = -1;
        ssize_t n;
        int r;

        assert(key_file);
        assert(ret_key);
        assert(ret_key_size);

        if (strv_isempty(search_path) || path_is_absolute(key_file)) {
                fd = open(key_file, O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to load key file '%s': %m", key_file);
        } else {
                char **i;

                STRV_FOREACH(i, search_path) {
                        _cleanup_free_ char *joined;

                        joined = path_join(*i, key_file);
                        if (!joined)
                                return log_oom();

                        fd = open(joined, O_RDONLY|O_CLOEXEC);
                        if (fd >= 0) {
                                discovered_path = TAKE_PTR(joined);
                                break;
                        }
                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to load key file '%s': %m", joined);
                }

                if (!discovered_path) {
                        /* Search path supplied, but file not found, report by returning NULL, but not failing */
                        *ret_key = NULL;
                        *ret_key_size = 0;
                        return 0;
                }

                assert(fd >= 0);
                key_file = discovered_path;
        }

        if (key_file_size == 0) {
                struct stat st;

                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat key file '%s': %m", key_file);

                r = stat_verify_regular(&st);
                if (r < 0)
                        return log_error_errno(r, "Key file is not a regular file: %m");

                if (st.st_size == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Key file is empty, refusing.");
                if ((uint64_t) st.st_size > KEY_FILE_SIZE_MAX) {
                        char buf1[FORMAT_BYTES_MAX], buf2[FORMAT_BYTES_MAX];
                        return log_error_errno(SYNTHETIC_ERRNO(ERANGE),
                                               "Key file larger (%s) than allowed maximum size (%s), refusing.",
                                               format_bytes(buf1, sizeof(buf1), st.st_size),
                                               format_bytes(buf2, sizeof(buf2), KEY_FILE_SIZE_MAX));
                }

                if (key_file_offset >= (uint64_t) st.st_size)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Key file offset too large for file, refusing.");

                key_file_size = st.st_size - key_file_offset;
        }

        buffer = malloc(key_file_size);
        if (!buffer)
                return log_oom();

        if (key_file_offset > 0)
                n = pread(fd, buffer, key_file_size, key_file_offset);
        else
                n = read(fd, buffer, key_file_size);
        if (n < 0)
                return log_error_errno(errno, "Failed to read key file '%s': %m", key_file);
        if (n == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Empty encrypted key found, refusing.");

        *ret_key = TAKE_PTR(buffer);
        *ret_key_size = (size_t) n;

        return 1;
}
