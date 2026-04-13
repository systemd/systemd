/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "fs-util.h"
#include "nulstr-util.h"
#include "path-lookup.h"
#include "portable-util.h"
#include "string-util.h"
#include "strv.h"

int portable_profile_dirs(RuntimeScope scope, char ***ret) {
        _cleanup_strv_free_ char **dirs = NULL;
        int r;

        assert(ret);

        switch (scope) {

        case RUNTIME_SCOPE_SYSTEM:
                r = strv_from_nulstr(&dirs, PORTABLE_PROFILE_DIRS);
                if (r < 0)
                        return r;

                break;

        case RUNTIME_SCOPE_USER: {
                _cleanup_free_ char *d = NULL;

                r = xdg_user_config_dir("systemd/portable/profile", &d);
                if (r < 0)
                        return r;

                r = strv_consume(&dirs, TAKE_PTR(d));
                if (r < 0)
                        return r;

                r = xdg_user_runtime_dir("systemd/portable/profile", &d);
                if (r < 0 && r != -ENXIO)
                        return r;
                if (r >= 0) {
                        r = strv_consume(&dirs, TAKE_PTR(d));
                        if (r < 0)
                                return r;
                }

                _fallthrough_;
        }

        case RUNTIME_SCOPE_GLOBAL:
                r = strv_extend_strv(
                                &dirs,
                                CONF_PATHS_STRV("systemd/user/portable/profile"),
                                /* filter_duplicates= */ false);
                if (r < 0)
                        return r;

                break;

        default:
                return -EINVAL;
        }

        *ret = TAKE_PTR(dirs);
        return 0;
}

int find_portable_profile(RuntimeScope scope, const char *name, const char *unit, char **ret_path) {
        _cleanup_strv_free_ char **dirs = NULL;
        const char *dot;
        int r;

        assert(name);
        assert(ret_path);

        assert_se(dot = strrchr(unit, '.'));

        r = portable_profile_dirs(scope, &dirs);
        if (r < 0)
                return r;

        STRV_FOREACH(p, dirs) {
                _cleanup_free_ char *joined = NULL;

                joined = strjoin(*p, "/", name, "/", dot + 1, ".conf");
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
