/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "creds-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "path-util.h"

bool credential_name_valid(const char *s) {
        /* We want that credential names are both valid in filenames (since that's our primary way to pass
         * them around) and as fdnames (which is how we might want to pass them around eventually) */
        return filename_is_valid(s) && fdname_is_valid(s);
}

int get_credentials_dir(const char **ret) {
        const char *e;

        assert(ret);

        e = secure_getenv("CREDENTIALS_DIRECTORY");
        if (!e)
                return -ENXIO;

        if (!path_is_absolute(e) || !path_is_normalized(e))
                return -EINVAL;

        *ret = e;
        return 0;
}

int read_credential(const char *name, void **ret, size_t *ret_size) {
        _cleanup_free_ char *fn = NULL;
        const char *d;
        int r;

        assert(ret);

        if (!credential_name_valid(name))
                return -EINVAL;

        r = get_credentials_dir(&d);
        if (r < 0)
                return r;

        fn = path_join(d, name);
        if (!fn)
                return -ENOMEM;

        return read_full_file_full(
                        AT_FDCWD, fn,
                        UINT64_MAX, SIZE_MAX,
                        READ_FULL_FILE_SECURE,
                        NULL,
                        (char**) ret, ret_size);
}
