/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "glob-util.h"
#include "log.h"
#include "nspawn-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"

int systemd_installation_has_version(const char *root, const char *minimal_version) {
        int r;

        /* Try to guess if systemd installation is later than the specified version. This
         * is hacky and likely to yield false negatives, particularly if the installation
         * is non-standard. False positives should be relatively rare.
         */

        FOREACH_STRING(pattern,
                       /* /lib works for systems without usr-merge, and for systems with a sane
                        * usr-merge, where /lib is a symlink to /usr/lib. /usr/lib is necessary
                        * for Gentoo which does a merge without making /lib a symlink.
                        * Also support multiarch paths von Debian/Ubuntu; *-linux-* is a small
                        * optimization based on the naming scheme of existing multiarch tuples.
                        */
                       "/lib/systemd/libsystemd-shared-*.so",
                       "/lib64/systemd/libsystemd-shared-*.so",
                       "/usr/lib/*-linux-*/systemd/libsystemd-shared-*.so",
                       "/usr/lib/systemd/libsystemd-shared-*.so",
                       "/usr/lib64/systemd/libsystemd-shared-*.so") {

                _cleanup_strv_free_ char **names = NULL;
                _cleanup_free_ char *path = NULL;
                char *c;

                path = path_join(root, pattern);
                if (!path)
                        return -ENOMEM;

                r = glob_extend(&names, path, 0);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return r;

                assert_se(c = endswith(path, "*.so"));
                *c = '\0'; /* truncate the glob part */

                STRV_FOREACH(name, names) {
                        /* This is most likely to run only once, hence let's not optimize anything. */
                        char *t, *t2;

                        t = startswith(basename(*name), "libsystemd-shared-");
                        if (!t)
                                continue;

                        t2 = endswith(t, ".so");
                        if (!t2)
                                continue;
                        *t2 = '\0';

                        r = strverscmp_improved(t, minimal_version);
                        log_debug("Found libsystemd shared at \"%s.so\", version %s (%s).",
                                  *name, t,
                                  r >= 0 ? "OK" : "too old");
                        if (r >= 0)
                                return true;
                }
        }

        return false;
}
