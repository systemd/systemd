/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "analyze.h"
#include "analyze-unit-shell.h"
#include "bus-error.h"
#include "bus-util.h"
#include "fd-util.h"
#include "log.h"
#include "namespace-util.h"
#include "process-util.h"
#include "runtime-scope.h"
#include "strv.h"
#include "unit-def.h"
#include "unit-name.h"

int verb_unit_shell(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *unit = NULL;
        int r;

        r = unit_name_mangle_with_suffix(argv[1], "as unit", UNIT_NAME_MANGLE_WARN, ".service", &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle name '%s': %m", argv[1]);

        r = acquire_bus(&bus, /* use_full_bus= */ NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        _cleanup_free_ char *object = unit_dbus_path_from_name(unit);
        if (!object)
                return log_oom();

        r = sd_bus_get_property(
                        bus,
                        "org.freedesktop.systemd1",
                        object,
                        "org.freedesktop.systemd1.Service",
                        "MainPID",
                        &error,
                        &reply,
                        "u");
        if (r < 0)
                return log_error_errno(r, "Failed to get the main PID of %s: %s", unit, bus_error_message(&error, r));

        pid_t pid;
        r = sd_bus_message_read(reply, "u", &pid);
        if (r < 0)
                return log_error_errno(r, "Failed to read the main PID of %s from reply: %m", unit);

        _cleanup_close_ int mntns_fd = -EBADF, root_fd = -EBADF, pidns_fd = -EBADF, netns_fd = -EBADF, userns_fd = -EBADF;
        r = namespace_open(
                        pid,
                        &pidns_fd,
                        &mntns_fd,
                        &netns_fd,
                        &userns_fd,
                        &root_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve FDs of %s namespace: %m", unit);

        pid_t child;
        r = namespace_fork(
                        "(unit-shell-ns)",
                        "(unit-shell)",
                        NULL, /* except_fds[] */
                        0, /* n_except_fds */
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL,
                        pidns_fd,
                        mntns_fd,
                        netns_fd,
                        userns_fd,
                        root_fd,
                        &child);
        if (r < 0)
                return log_error_errno(r, "Failed to fork and enter the namespace of %s: %m", unit);

        if (r == 0) {
                _cleanup_strv_free_ char **args = NULL;
                if (argc > 2) {
                        args = strv_copy(strv_skip(argv, 2));
                        if (!args)
                                return log_oom();
                }

                if (args) {
                        r = execvp(args[0], args);
                        if (r < 0)
                                log_error_errno(errno, "Failed to execute '%s': %m", *args);
                } else {
                        execl(DEFAULT_USER_SHELL, "-" DEFAULT_USER_SHELL_NAME, NULL);
                        if (r < 0)
                                log_debug_errno(errno, "%m ignored");
                        if (!streq(DEFAULT_USER_SHELL, "/bin/bash")) {
                                r = execl("/bin/bash", "-bash", NULL);
                                if (r < 0)
                                        log_debug_errno(errno, "%m ignored");
                        }
                        if (!streq(DEFAULT_USER_SHELL, "/bin/sh")) {
                                r = execl("/bin/sh", "-sh", NULL);
                                if (r < 0)
                                        log_debug_errno(errno, "%m ignored");
                        }
                }
                _exit(EXIT_FAILURE);
        }

        return wait_for_terminate_and_check(
                "(unit-shell)",
                child,
                WAIT_LOG_ABNORMAL|WAIT_LOG_NON_ZERO_EXIT_STATUS);
}
