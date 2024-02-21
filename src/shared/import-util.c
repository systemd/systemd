/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "alloc-util.h"
#include "btrfs-util.h"
#include "chattr-util.h"
#include "errno-util.h"
#include "import-util.h"
#include "log.h"
#include "macro.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "string-table.h"
#include "string-util.h"

static const char *skip_protocol_and_hostname(const char *url) {
        const char *d;
        size_t n;

        /* A very very lenient implementation of RFC3986 Section 3.2 */

        /* Find colon separating protocol and hostname */
        d = strchr(url, ':');
        if (!d || url == d)
                return NULL;
        d++;

        /* Skip slashes after colon */
        d += strspn(d, "/");

        /* Skip everything till next slash or end */
        n = strcspn(d, "/?#");
        if (n == 0)
                return NULL;

        return d + n;
}

int import_url_last_component(
                const char *url,
                char **ret) {

        const char *e, *p, *h;

        /* This extracts the last path component of the specified URI, i.e. the last non-empty substrings
         * between two "/" characters. This ignores "Query" and "Fragment" suffixes (as per RFC3986). */

        h = skip_protocol_and_hostname(url);
        if (!h)
                return -EINVAL;

        e = h + strcspn(h, "?#"); /* Cut off "Query" and "Fragment" */

        while (e > h && e[-1] == '/') /* Eat trailing slashes */
                e--;

        p = e;
        while (p > h && p[-1] != '/') /* Find component before that */
                p--;

        if (e <= p) /* Empty component? */
                return -EADDRNOTAVAIL;

        if (ret) {
                char *s;

                s = strndup(p, e - p);
                if (!s)
                        return -ENOMEM;

                *ret = s;
        }

        return 0;
}

int import_url_change_suffix(
                const char *url,
                size_t n_drop_components,
                const char *suffix,
                char **ret) {

        const char *e, *h;
        char *s;

        assert(url);
        assert(ret);

        /* This drops the specified number of path components of the specified URI, i.e. the specified number
         * of non-empty substring between two "/" characters from the end of the string, and then append the
         * specified suffix instead. Before doing all this it chops off the "Query" and "Fragment" suffixes
         * (they are *not* re-added to the final URL). Note that n_drop_components may be 0 (in which case the
         * component are simply added to the end). The suffix may be specified as NULL or empty string in
         * which case nothing is appended, only the specified number of components chopped off. Note that the
         * function may be called with n_drop_components == 0 and suffix == NULL, in which case the "Query"
         * and "Fragment" is chopped off, and ensured the URL ends in a single "/", and that's it. */

        h = skip_protocol_and_hostname(url);
        if (!h)
                return -EINVAL;

        e = h + strcspn(h, "?#"); /* Cut off "Query" and "Fragment" */

        while (e > h && e[-1] == '/') /* Eat trailing slashes */
                e--;

        /* Drop the specified number of components from the end. Note that this is pretty lenient: if there
         * are less component we silently drop those and then append the suffix to the top. */
        while (n_drop_components > 0) {
                while (e > h && e[-1] != '/') /* Eat last word (we don't mind if empty) */
                        e--;

                while (e > h && e[-1] == '/') /* Eat slashes before the last word */
                        e--;

                n_drop_components--;
        }

        s = new(char, (e - url) + 1 + strlen_ptr(suffix) + 1);
        if (!s)
                return -ENOMEM;

        strcpy(stpcpy(mempcpy(s, url, e - url), "/"), strempty(suffix));
        *ret = s;
        return 0;
}

static const char* const import_verify_table[_IMPORT_VERIFY_MAX] = {
        [IMPORT_VERIFY_NO] = "no",
        [IMPORT_VERIFY_CHECKSUM] = "checksum",
        [IMPORT_VERIFY_SIGNATURE] = "signature",
};

DEFINE_STRING_TABLE_LOOKUP(import_verify, ImportVerify);

static const char* const import_compress_type_table[_IMPORT_COMPRESS_TYPE_MAX] = {
        [IMPORT_COMPRESS_UNKNOWN]      = "unknown",
        [IMPORT_COMPRESS_UNCOMPRESSED] = "uncompressed",
        [IMPORT_COMPRESS_XZ]           = "xz",
        [IMPORT_COMPRESS_GZIP]         = "gzip",
        [IMPORT_COMPRESS_BZIP2]        = "bzip2",
        [IMPORT_COMPRESS_ZSTD]         = "zstd",
};

DEFINE_STRING_TABLE_LOOKUP(import_compress_type, ImportCompressType);

ImportCompressType tar_filename_to_compression(const char *name) {

        if (!name)
                return IMPORT_COMPRESS_UNCOMPRESSED;

        if (ENDSWITH_SET(name, ".xz", ".txz"))
                return IMPORT_COMPRESS_XZ;
        else if (ENDSWITH_SET(name, ".gz", ".tgz"))
                return IMPORT_COMPRESS_GZIP;
        else if (ENDSWITH_SET(name, ".bz2", ".tbz2"))
                return IMPORT_COMPRESS_BZIP2;
        else if (ENDSWITH_SET(name, ".zst", ".tzst"))
                return IMPORT_COMPRESS_ZSTD;

        return IMPORT_COMPRESS_UNCOMPRESSED;
}

ImportCompressType raw_filename_to_compression(const char *name) {

        if (!name)
                return IMPORT_COMPRESS_UNCOMPRESSED;

        if (endswith(name, ".xz"))
                return IMPORT_COMPRESS_XZ;
        else if (endswith(name, ".gz"))
                return IMPORT_COMPRESS_GZIP;
        else if (endswith(name, ".bz2"))
                return IMPORT_COMPRESS_BZIP2;
        else if (endswith(name, ".zst"))
                return IMPORT_COMPRESS_ZSTD;

        return IMPORT_COMPRESS_UNCOMPRESSED;
}

int tar_strip_suffixes(const char *name, char **ret) {

        static const char suffixes[] =
                ".tar\0"
                ".tar.gz\0"
                ".tar.bz2\0"
                ".tar.xz\0"
                ".tar.zst\0"
                ".tgz\0"
                ".tbz2\0"
                ".txz\0"
                ".tzst\0"
        ;

        const char *e;
        char *s;

        assert(name);
        assert(ret);

        NULSTR_FOREACH(sfx, suffixes) {
                e = endswith(name, sfx);
                if (e)
                        break;
        }
        if (!e)
                e = strchr(name, 0);

        if (e <= name)
                return -EINVAL;

        s = strndup(name, e - name);
        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

int raw_strip_suffixes(const char *p, char **ret) {

        static const char suffixes[] =
                ".xz\0"
                ".gz\0"
                ".bz2\0"
                ".zst\0"
                ".sysext.raw\0"
                ".confext.raw\0"
                ".raw\0"
                ".qcow2\0"
                ".img\0"
                ".bin\0";

        _cleanup_free_ char *q = NULL;

        q = strdup(p);
        if (!q)
                return -ENOMEM;

        for (;;) {
                bool changed = false;

                NULSTR_FOREACH(sfx, suffixes) {
                        char *e;

                        e = endswith(q, sfx);
                        if (e) {
                                *e = 0;
                                changed = true;
                        }
                }

                if (!changed)
                        break;
        }

        *ret = TAKE_PTR(q);

        return 0;
}

int import_assign_pool_quota_and_warn(const char *path) {
        int r;

        assert(path);

        r = btrfs_subvol_auto_qgroup(path, 0, true);
        if (r == -ENOTTY) {
                log_debug_errno(r, "Failed to set up quota hierarchy for %s, as directory is not on btrfs or not a subvolume. Ignoring.", path);
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to set up default quota hierarchy for %s: %m", path);
        if (r > 0)
                log_debug("Set up default quota hierarchy for %s.", path);

        return 0;
}

int import_set_nocow_and_log(int fd, const char *path) {
        int r;

        r = chattr_fd(fd, FS_NOCOW_FL, FS_NOCOW_FL, NULL);
        if (r < 0)
                return log_full_errno(
                                ERRNO_IS_NOT_SUPPORTED(r) ? LOG_DEBUG : LOG_WARNING,
                                r, "Failed to set file attributes on %s: %m", path);

        return 0;
}
