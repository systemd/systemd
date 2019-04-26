/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <unistd.h>

#include "fs-util.h"
#include "generator.h"
#include "log.h"
#include "proc-cmdline.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

/*
 * Implements the logic described in systemd.offline-updates(7).
 */

static const char *arg_dest = NULL;

static int generate_symlink(void) {
        const char *fn;
        FOREACH_STRING(fn, "/system-update", "/etc/system-update") {
                int r = laccess(fn, F_OK);
                if (r == 0) {
                        const char *p = strjoina(arg_dest, "/" SPECIAL_DEFAULT_TARGET);
                        if (symlink(SYSTEM_DATA_UNIT_PATH "/system-update.target", fn) < 0)
                                return log_error_errno(errno, "Failed to create symlink %s: %m", p);
                        return 1;
                }
                if (r != ENOENT) {
                        log_error_errno(errno, "Failed to check %s for system update: %m", fn);
                        return -EINVAL;
                }
        }

        /* neither file was found */
        return 0;
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        assert(key);

        /* Check if a run level is specified on the kernel command line. The
         * command line has higher priority than any on-disk configuration, so
         * it'll make any symlink we create moot.
         */

        if (streq(key, "systemd.unit") && !proc_cmdline_value_missing(key, value))
                log_warning("Offline system update overridden by kernel command line systemd.unit= setting");
        else if (!value && runlevel_to_target(key))
                log_warning("Offline system update overridden by runlevel \"%s\" on the kernel command line", key);

        return 0;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r;

        assert_se(arg_dest = dest_early);

        r = generate_symlink();
        if (r < 0)
                return r;

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        return 0;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
