/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "log.h"
#include "netdev.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-verify.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"

/* networkd only warns about unknown sections, unknown keys and unparsable values and then ignores them. For
 * verification that is exactly what we want to catch, so count them. */
static void log_syntax_callback(const char *unit, int level, void *userdata) {
        unsigned *n = ASSERT_PTR(userdata);

        if (level <= LOG_WARNING)
                (*n)++;
}

int networkd_verify_files(char **files) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        _unused_ _cleanup_(clear_log_syntax_callback) dummy_t dummy;
        unsigned n_warnings = 0;
        int r, ret = 0;

        if (strv_isempty(files))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected at least one .network or .netdev file to verify.");

        r = manager_new(&manager, /* test_mode= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate manager: %m");

        set_log_syntax_callback(log_syntax_callback, &n_warnings);

        STRV_FOREACH(f, files) {
                _cleanup_free_ char *path = NULL;
                unsigned n = n_warnings;

                /* The loaders open relative paths below the root fd, not the cwd. */
                r = path_make_absolute_cwd(*f, &path);
                if (r < 0)
                        return log_error_errno(r, "Failed to make path '%s' absolute: %m", *f);

                if (endswith(path, ".network"))
                        r = network_load_one(manager, &manager->networks, path);
                else if (endswith(path, ".netdev")) {
                        _cleanup_(netdev_unrefp) NetDev *netdev = NULL;

                        r = netdev_load_one(manager, path, &netdev);
                } else
                        r = log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s: not a .network or .netdev file.", *f);

                if (r < 0)
                        RET_GATHER(ret, log_error_errno(r, "%s: failed to load.", *f));
                else if (n_warnings > n)
                        RET_GATHER(ret, log_error_errno(SYNTHETIC_ERRNO(EINVAL), "%s: loaded with %u warning(s).", *f, n_warnings - n));
        }

        return ret;
}
