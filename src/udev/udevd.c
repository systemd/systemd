/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2004 Chris Friesen <chris_friesen@sympatico.ca>
 * Copyright © 2009 Canonical Ltd.
 * Copyright © 2009 Scott James Remnant <scott@netsplit.com>
 */

#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "mkdir.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "selinux-util.h"
#include "terminal-util.h"
#include "udev-config.h"
#include "udev-manager.h"
#include "udevd.h"
#include "version.h"

int run_udevd(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *manager = NULL;
        int r;

        log_setup();

        manager = manager_new();
        if (!manager)
                return log_oom();

        r = manager_load(manager, argc, argv);
        if (r <= 0)
                return r;

        r = must_be_root();
        if (r < 0)
                return r;

        /* set umask before creating any file/directory */
        umask(022);

        r = mac_init();
        if (r < 0)
                return r;

        /* Make sure we can have plenty fds (for example for pidfds) */
        (void) rlimit_nofile_bump(-1);

        r = RET_NERRNO(mkdir("/run/udev", 0755));
        if (r < 0 && r != -EEXIST)
                return log_error_errno(r, "Failed to create /run/udev: %m");

        r = manager_init(manager);
        if (r < 0)
                return r;

        if (arg_daemonize) {
                pid_t pid;

                log_info("Starting systemd-udevd version " GIT_VERSION);

                /* connect /dev/null to stdin, stdout, stderr */
                if (log_get_max_level() < LOG_DEBUG) {
                        r = make_null_stdio();
                        if (r < 0)
                                log_warning_errno(r, "Failed to redirect standard streams to /dev/null: %m");
                }

                pid = fork();
                if (pid < 0)
                        return log_error_errno(errno, "Failed to fork daemon: %m");
                if (pid > 0)
                        /* parent */
                        return 0;

                /* child */
                terminal_detach_session();
        }

        return manager_main(manager);
}
