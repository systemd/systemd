/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot spawn a unit shell for a remote service.");

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
        if (pid == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "Unit %s has no MainPID (hint: inactive?)", unit);

        _cleanup_close_ int mntns_fd = -EBADF, root_fd = -EBADF, pidns_fd = -EBADF, netns_fd = -EBADF, userns_fd = -EBADF;
        r = namespace_open(
                        pid,
                        &pidns_fd,
                        &mntns_fd,
                        &netns_fd,
                        &userns_fd,
                        &root_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve FDs of namespaces of %s: %m", unit);

        _cleanup_strv_free_ char **args = NULL;
        if (argc > 2) {
                args = strv_copy(strv_skip(argv, 2));
                if (!args)
                        return log_oom();
        }

        pid_t child;
        r = namespace_fork(
                        "(unit-shell-ns)",
                        "(unit-shell)",
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
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
                if (args) {
                        (void) execvp(args[0], args);
                        log_error_errno(errno, "Failed to execute '%s': %m", *args);
                } else {
                        (void) execl(DEFAULT_USER_SHELL, "-" DEFAULT_USER_SHELL_NAME, NULL);
                        log_debug_errno(errno, "Failed to execute '" DEFAULT_USER_SHELL "', ignoring: %m");

                        if (!streq(DEFAULT_USER_SHELL, "/bin/bash")) {
                                (void) execl("/bin/bash", "-bash", NULL);
                                log_debug_errno(errno, "Failed to execute '/bin/bash', ignoring: %m");
                        }

                        if (!streq(DEFAULT_USER_SHELL, "/bin/sh")) {
                                (void) execl("/bin/sh", "-sh", NULL);
                                log_debug_errno(errno, "Failed to execute '/bin/sh', ignoring: %m");
                        }

                        log_error_errno(errno, "Failed to execute '" DEFAULT_USER_SHELL "', '/bin/bash', and '/bin/sh': %m");
                }
                _exit(EXIT_FAILURE);
        }

        return wait_for_terminate_and_check(
                        "(unit-shell)",
                        child,
                        WAIT_LOG_ABNORMAL|WAIT_LOG_NON_ZERO_EXIT_STATUS);
}
