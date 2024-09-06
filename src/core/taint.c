/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/utsname.h>

#include "alloc-util.h"
#include "cgroup-util.h"
#include "clock-util.h"
#include "errno-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "os-util.h"
#include "path-util.h"
#include "strv.h"
#include "taint.h"
#include "uid-range.h"

static int short_uid_gid_range(UIDRangeUsernsMode mode) {
        _cleanup_(uid_range_freep) UIDRange *p = NULL;
        int r;

        /* Taint systemd if we the UID/GID range assigned to this environment doesn't at least cover 0…65534,
         * i.e. from root to nobody. */

        r = uid_range_load_userns(/* path= */ NULL, mode, &p);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return false;
        if (r < 0)
                return log_debug_errno(r, "Failed to load uid_map or gid_map: %m");

        return !uid_range_covers(p, 0, 65535);
}

char** taint_strv(void) {
        const char *stage[12] = {};
        size_t n = 0;

        /* Returns a "taint string", e.g. "local-hwclock:var-run-bad". Only things that are detected at
         * runtime should be tagged here. For stuff that is known during compilation, emit a warning in the
         * configuration phase. */

        _cleanup_free_ char *bin = NULL, *usr_sbin = NULL, *var_run = NULL;

        if (readlink_malloc("/bin", &bin) < 0 || !PATH_IN_SET(bin, "usr/bin", "/usr/bin"))
                stage[n++] = "unmerged-usr";

        /* Note that the check is different from default_PATH(), as we want to taint on uncanonical symlinks
         * too. */
        if (readlink_malloc("/usr/sbin", &usr_sbin) < 0 || !PATH_IN_SET(usr_sbin, "bin", "/usr/bin"))
                stage[n++] = "unmerged-bin";

        if (readlink_malloc("/var/run", &var_run) < 0 || !PATH_IN_SET(var_run, "../run", "/run"))
                stage[n++] = "var-run-bad";

        if (cg_all_unified() == 0)
                stage[n++] = "cgroupsv1";

        if (clock_is_localtime(NULL) > 0)
                stage[n++] = "local-hwclock";

        if (os_release_support_ended(NULL, /* quiet= */ true, NULL) > 0)
                stage[n++] = "support-ended";

        struct utsname uts;
        assert_se(uname(&uts) >= 0);
        if (strverscmp_improved(uts.release, KERNEL_BASELINE_VERSION) < 0)
                stage[n++] = "old-kernel";

        _cleanup_free_ char *overflowuid = NULL, *overflowgid = NULL;
        if (read_one_line_file("/proc/sys/kernel/overflowuid", &overflowuid) >= 0 &&
            !streq(overflowuid, "65534"))
                stage[n++] = "overflowuid-not-65534";
        if (read_one_line_file("/proc/sys/kernel/overflowgid", &overflowgid) >= 0 &&
            !streq(overflowgid, "65534"))
                stage[n++] = "overflowgid-not-65534";

        if (short_uid_gid_range(UID_RANGE_USERNS_INSIDE) > 0)
                stage[n++] = "short-uid-range";
        if (short_uid_gid_range(GID_RANGE_USERNS_INSIDE) > 0)
                stage[n++] = "short-gid-range";

        assert(n < ELEMENTSOF(stage) - 1);  /* One extra for NULL terminator */

        return strv_copy((char *const *) stage);
}

char* taint_string(void) {
        _cleanup_strv_free_ char **taints = NULL;

        taints = taint_strv();
        if (!taints)
                return NULL;

        return strv_join(taints, ":");
}
