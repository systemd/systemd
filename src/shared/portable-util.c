/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fs-util.h"
#include "nulstr-util.h"
#include "portable-util.h"
#include "string-util.h"

int find_portable_profile(const char *name, const char *unit, char **ret_path) {
        const char *dot;
        int r;

        assert(name);
        assert(ret_path);

        assert_se(dot = strrchr(unit, '.'));

        NULSTR_FOREACH(p, PORTABLE_PROFILE_DIRS) {
                _cleanup_free_ char *joined = NULL;

                joined = strjoin(p, "/", name, "/", dot + 1, ".conf");
                if (!joined)
                        return -ENOMEM;

                r = access_nofollow(joined, F_OK);
                if (r >= 0) {
                        *ret_path = TAKE_PTR(joined);
                        return 0;
                }
                if (r != -ENOENT)
                        return r;
        }

        return -ENOENT;
}
