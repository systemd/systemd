/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdio.h>

#include "alloc-util.h"
#include "fstab-util.h"
#include "log.h"
#include "mkdir.h"
#include "proc-cmdline.h"
#include "special.h"
#include "string-util.h"
#include "unit-name.h"
#include "util.h"

static const char *arg_dest = "/tmp";
static char *arg_resume_device = NULL;

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {

        if (streq(key, "resume")) {
                char *s;

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                s = fstab_node_to_udev_node(value);
                if (!s)
                        return log_oom();

                free(arg_resume_device);
                arg_resume_device = s;
        }

        return 0;
}

static int process_resume(void) {
        _cleanup_free_ char *name = NULL, *lnk = NULL;
        int r;

        if (!arg_resume_device)
                return 0;

        r = unit_name_from_path_instance("systemd-hibernate-resume", arg_resume_device, ".service", &name);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        lnk = strjoin(arg_dest, "/" SPECIAL_SYSINIT_TARGET ".wants/", name);
        if (!lnk)
                return log_oom();

        mkdir_parents_label(lnk, 0755);
        if (symlink(SYSTEM_DATA_UNIT_PATH "/systemd-hibernate-resume@.service", lnk) < 0)
                return log_error_errno(errno, "Failed to create symlink %s: %m", lnk);

        return 0;
}

int main(int argc, char *argv[]) {
        int r = 0;

        log_set_prohibit_ipc(true);
        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argc > 1 && argc != 4) {
                log_error("This program takes three or no arguments.");
                return EXIT_FAILURE;
        }

        if (argc > 1)
                arg_dest = argv[1];

        /* Don't even consider resuming outside of initramfs. */
        if (!in_initrd()) {
                log_debug("Not running in an initrd, quitting.");
                return EXIT_SUCCESS;
        }

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        r = process_resume();
        free(arg_resume_device);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
