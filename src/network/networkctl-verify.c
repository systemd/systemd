/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "errno-util.h"
#include "hashmap.h"
#include "log.h"
#include "netdev.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkctl-verify.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"

/* Only the configuration parser reports through log_syntax(): unknown sections and keys, unparsable
 * values. networkd logs those and drops the setting, which is exactly what verification is for, so any
 * of them fails the file. Plain log_warning() calls elsewhere do not reach this hook. */
static void log_syntax_callback(const char *unit, int level, void *userdata) {
        bool *warned = ASSERT_PTR(userdata);

        if (level <= LOG_WARNING)
                *warned = true;
}

/* Returns > 0 if the file was skipped the way the daemon would skip it, 0 if it verified, < 0 on
 * failure. Failures are logged here or by the loaders. */
static int verify_one(Manager *manager, const char *path, bool is_netdev, bool *warned) {
        int r;

        assert(manager);
        assert(path);
        assert(warned);

        /* The loaders disagree on empty and masked files; settle it before they see the file. */
        r = null_or_empty_path(path);
        if (r < 0)
                return log_error_errno(r, "Failed to check '%s': %m", path);
        if (r > 0) {
                log_notice("'%s': Masked or empty, skipping.", path);
                return 1;
        }

        *warned = false;

        if (is_netdev) {
                _cleanup_(netdev_unrefp) NetDev *netdev = NULL;

                r = netdev_load_one(manager, path, &netdev);
                if (r >= 0) {
                        /* Attach so that .network files verified later resolve Bridge=, Bond=, VLAN=
                         * and friends against it, as they would in the daemon. */
                        r = netdev_attach(netdev);
                        if (r >= 0)
                                TAKE_PTR(netdev);
                }
        } else {
                /* Per file, not the manager's map: it is keyed by file stem, and the daemon never sees
                 * two files with the same name because it enumerates directories. */
                _cleanup_(ordered_hashmap_freep) OrderedHashmap *networks = NULL;

                r = network_load_one(manager, &networks, path);
        }
        /* Checked first: a file the daemon would skip has still been parsed in full. */
        if (*warned)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "'%s': The configuration parser reported problems, see above.", path);
        if (r == -ESTALE) {
                log_notice("'%s': Conditions do not match this host, skipping.", path);
                return 1;
        }
        if (r < 0)
                return r; /* The loaders log internally. */

        return 0;
}

int verb_verify(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        _cleanup_strv_free_ char **netdevs = NULL, **networks = NULL;
        _unused_ _cleanup_(clear_log_syntax_callback) dummy_t dummy;
        bool warned = false;
        int r, ret = 0;

        STRV_FOREACH(f, strv_skip(argv, 1)) {
                _cleanup_free_ char *path = NULL;

                /* Drop-ins are looked up by basename in the usual configuration directories, so an
                 * absolute path only settles where the file itself is read from. */
                r = path_make_absolute_cwd(*f, &path);
                if (r < 0) {
                        RET_GATHER(ret, log_error_errno(r, "Failed to make path '%s' absolute: %m", *f));
                        continue;
                }

                if (endswith(path, ".netdev"))
                        r = strv_consume(&netdevs, TAKE_PTR(path));
                else if (endswith(path, ".network"))
                        r = strv_consume(&networks, TAKE_PTR(path));
                else {
                        RET_GATHER(ret, log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                        "'%s': Not a .network or .netdev file.", *f));
                        continue;
                }
                if (r < 0)
                        return log_oom();
        }

        /* The same netdev twice would be a name clash with itself. */
        strv_uniq(netdevs);
        strv_uniq(networks);

        r = manager_new(&manager, /* test_mode= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate manager: %m");

        /* Ensure we have at least warnings enabled even if SYSTEMD_LOG_LEVEL= lowers the level. */
        log_set_max_level(MAX(log_get_max_level(), LOG_WARNING));
        set_log_syntax_callback(log_syntax_callback, &warned);

        /* Netdevs first, whatever the argument order, so .network files can refer to them. */
        STRV_FOREACH(p, netdevs)
                RET_GATHER(ret, verify_one(manager, *p, /* is_netdev= */ true, &warned));
        STRV_FOREACH(p, networks)
                RET_GATHER(ret, verify_one(manager, *p, /* is_netdev= */ false, &warned));

        return ret;
}
