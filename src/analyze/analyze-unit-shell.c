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
#include "pidref.h"
#include "runtime-scope.h"
#include "strv.h"

static int get_unit_object(sd_bus *bus, char *service, const char **object) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        assert(bus);
        assert(service);

        r = sd_bus_call_method(bus,
                               "org.freedesktop.systemd1",
                               "/org/freedesktop/systemd1",
                               "org.freedesktop.systemd1.Manager",
                               "GetUnit",
                               &error,
                               &reply,
                               "s",
                               service);
        if (r < 0)
                return log_error_errno(r, "Failed to call GetUnit on '%s': %s", service, bus_error_message(&error, r));

        return sd_bus_message_read(reply, "o", object);
}

int verb_unit_shell(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        if (!(sd_bus_service_name_is_valid(argv[1])))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "D-Bus service name '%s' is not valid.", argv[1]);

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        const char *object = NULL;
        r = get_unit_object(bus, argv[1], &object);
        if (r < 0)
                return log_error_errno(r, "Failed to get unit object of service %s, ignoring: %m", argv[1]);

        r = sd_bus_get_property(bus,
                                "org.freedesktop.systemd1",
                                object,
                                "org.freedesktop.systemd1.Service",
                                "MainPID",
                                &error,
                                &reply,
                                "u");
        if (r < 0)
                return log_error_errno(r, "Failed to get PID: %s", bus_error_message(&error, r));

        pid_t pid;
        r = sd_bus_message_read(reply, "u", &pid);
        if (r < 0)
                return log_error_errno(r, "Failed to read PID from reply: %m");

        PidRef p = PIDREF_MAKE_FROM_PID(pid);
        _cleanup_close_ int mntns_fd = -EBADF, root_fd = -EBADF, pidns_fd = -EBADF;
        r = pidref_namespace_open(&p,
                                  &pidns_fd,
                                  &mntns_fd,
                                  NULL, /* ret_netns_fd */
                                  NULL, /* ret_userns_fd */
                                  &root_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve FDs of the target process' namespace: %m");

        pid_t child;
        r = namespace_fork("(unit-shell)",
                           "(unit-shell)",
                           NULL, /* except_fds[] */
                           0, /* n_except_fds */
                           FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL,
                           pidns_fd,
                           mntns_fd,
                           -EBADF, /* netns_fd */
                           -EBADF, /* userns_fd */
                           root_fd,
                           &child);

        if (r < 0)
                return log_error_errno(r, "Failed to fork the namespace: %m");

        if (r == 0) {
                execl("/bin/bash", "bash", NULL);
                exit(EXIT_FAILURE);
        }

        int status;
        r = waitpid(child, &status, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for child PID %d: %m", child);

        return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
