/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cryptsetup-keyfile.h"
#include "fileio.h"
#include "path-util.h"
#include "strv.h"

int find_key_file(
                const char *key_file,
                char **search_path,
                const char *bindname,
                void **ret_key,
                size_t *ret_key_size) {

        int r;

        assert(key_file);
        assert(ret_key);
        assert(ret_key_size);

        if (strv_isempty(search_path) || path_is_absolute(key_file)) {

                r = read_full_file_full(
                                AT_FDCWD, key_file, UINT64_MAX, SIZE_MAX,
                                READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|READ_FULL_FILE_CONNECT_SOCKET,
                                bindname,
                                (char**) ret_key, ret_key_size);
                if (r == -E2BIG)
                        return log_error_errno(r, "Key file '%s' too large.", key_file);
                if (r < 0)
                        return log_error_errno(r, "Failed to load key file '%s': %m", key_file);

                return 1;
        }

        STRV_FOREACH(i, search_path) {
                _cleanup_free_ char *joined = NULL;

                joined = path_join(*i, key_file);
                if (!joined)
                        return log_oom();

                r = read_full_file_full(
                                AT_FDCWD, joined, UINT64_MAX, SIZE_MAX,
                                READ_FULL_FILE_SECURE|READ_FULL_FILE_WARN_WORLD_READABLE|READ_FULL_FILE_CONNECT_SOCKET,
                                bindname,
                                (char**) ret_key, ret_key_size);
                if (r >= 0)
                        return 1;
                if (r == -E2BIG) {
                        log_warning_errno(r, "Key file '%s' too large, ignoring.", key_file);
                        continue;
                }
                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to load key file '%s': %m", key_file);
        }

        /* Search path supplied, but file not found, report by returning NULL, but not failing */
        *ret_key = NULL;
        *ret_key_size = 0;
        return 0;
}
