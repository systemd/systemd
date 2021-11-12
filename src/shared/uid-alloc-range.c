/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "chase-symlinks.h"
#include "fd-util.h"
#include "fileio.h"
#include "string-util.h"
#include "uid-alloc-range.h"
#include "user-util.h"

#if ENABLE_COMPAT_MUTABLE_UID_BOUNDARIES
static int parse_alloc_uid(const char *path, const char *name, const char *t, uid_t *ret_uid) {
        uid_t uid;
        int r;

        r = parse_uid(t, &uid);
        if (r < 0)
                return log_debug_errno(r, "%s: failed to parse %s %s, ignoring: %m", path, name, t);
        if (uid == 0)
                uid = 1;

        *ret_uid = uid;
        return 0;
}
#endif

int read_login_defs(UGIDAllocationRange *ret_defs, const char *path, const char *root) {
        UGIDAllocationRange defs = {
                .system_alloc_uid_min = SYSTEM_ALLOC_UID_MIN,
                .system_uid_max = SYSTEM_UID_MAX,
                .system_alloc_gid_min = SYSTEM_ALLOC_GID_MIN,
                .system_gid_max = SYSTEM_GID_MAX,
        };

#if ENABLE_COMPAT_MUTABLE_UID_BOUNDARIES
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        if (!path)
                path = "/etc/login.defs";

        r = chase_symlinks_and_fopen_unlocked(path, root, CHASE_PREFIX_ROOT, "re", NULL, &f);
        if (r == -ENOENT)
                goto assign;
        if (r < 0)
                return log_debug_errno(r, "Failed to open %s: %m", path);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *t;

                r = read_line(f, LINE_MAX, &line);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read %s: %m", path);
                if (r == 0)
                        break;

                if ((t = first_word(line, "SYS_UID_MIN")))
                        (void) parse_alloc_uid(path, "SYS_UID_MIN", t, &defs.system_alloc_uid_min);
                else if ((t = first_word(line, "SYS_UID_MAX")))
                        (void) parse_alloc_uid(path, "SYS_UID_MAX", t, &defs.system_uid_max);
                else if ((t = first_word(line, "SYS_GID_MIN")))
                        (void) parse_alloc_uid(path, "SYS_GID_MIN", t, &defs.system_alloc_gid_min);
                else if ((t = first_word(line, "SYS_GID_MAX")))
                        (void) parse_alloc_uid(path, "SYS_GID_MAX", t, &defs.system_gid_max);
        }

 assign:
        if (defs.system_alloc_uid_min > defs.system_uid_max) {
                log_debug("%s: SYS_UID_MIN > SYS_UID_MAX, resetting.", path);
                defs.system_alloc_uid_min = MIN(defs.system_uid_max - 1, (uid_t) SYSTEM_ALLOC_UID_MIN);
                /* Look at sys_uid_max to make sure sys_uid_min..sys_uid_max remains a valid range. */
        }
        if (defs.system_alloc_gid_min > defs.system_gid_max) {
                log_debug("%s: SYS_GID_MIN > SYS_GID_MAX, resetting.", path);
                defs.system_alloc_gid_min = MIN(defs.system_gid_max - 1, (gid_t) SYSTEM_ALLOC_GID_MIN);
                /* Look at sys_gid_max to make sure sys_gid_min..sys_gid_max remains a valid range. */
        }
#endif

        *ret_defs = defs;
        return 0;
}

const UGIDAllocationRange *acquire_ugid_allocation_range(void) {
#if ENABLE_COMPAT_MUTABLE_UID_BOUNDARIES
        static thread_local UGIDAllocationRange defs = {
#else
        static const UGIDAllocationRange defs = {
#endif
                .system_alloc_uid_min = SYSTEM_ALLOC_UID_MIN,
                .system_uid_max = SYSTEM_UID_MAX,
                .system_alloc_gid_min = SYSTEM_ALLOC_GID_MIN,
                .system_gid_max = SYSTEM_GID_MAX,
        };

#if ENABLE_COMPAT_MUTABLE_UID_BOUNDARIES
        /* This function will ignore failure to read the file, so it should only be called from places where
         * we don't crucially depend on the answer. In other words, it's appropriate for journald, but
         * probably not for sysusers. */

        static thread_local bool initialized = false;

        if (!initialized) {
                (void) read_login_defs(&defs, NULL, NULL);
                initialized = true;
        }
#endif

        return &defs;
}

bool uid_is_system(uid_t uid) {
        const UGIDAllocationRange *defs;
        assert_se(defs = acquire_ugid_allocation_range());

        return uid <= defs->system_uid_max;
}

bool gid_is_system(gid_t gid) {
        const UGIDAllocationRange *defs;
        assert_se(defs = acquire_ugid_allocation_range());

        return gid <= defs->system_gid_max;
}
