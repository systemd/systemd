/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <unistd.h>

#include "fs-util.h"
#include "generator.h"
#include "initrd-util.h"
#include "log.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "special.h"
#include "string-util.h"
#include "unit-file.h"

/*
 * Implements the logic described in systemd.offline-updates(7).
 */

static const char *arg_dest = NULL;

static int generate_symlink(void) {
        int r;

        FOREACH_STRING(p, "/system-update", "/etc/system-update") {
                r = access_nofollow(p, F_OK);
                if (r < 0) {
                        if (r != -ENOENT)
                                log_warning_errno(r, "Failed to check if %s symlink exists, ignoring: %m", p);
                        continue;
                }

                _cleanup_free_ char *j = NULL;

                j = path_join(arg_dest, SPECIAL_DEFAULT_TARGET);
                if (!j)
                        return log_oom();

                if (symlink(SYSTEM_DATA_UNIT_DIR "/system-update.target", j) < 0)
                        return log_error_errno(errno, "Failed to create symlink %s: %m", j);

                return 1;
        }

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

        if (in_initrd()) {
                log_debug("Skipping generator, running in the initrd.");
                return EXIT_SUCCESS;
        }

        r = generate_symlink();
        if (r <= 0)
                return r;

        /* We parse the command line only to emit warnings. */
        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        return 0;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
