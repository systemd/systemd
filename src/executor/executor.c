/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "alloc-util.h"
#include "build.h"
#include "execute-serialize.h"
#include "exit-status.h"
#include "fdset.h"
#include "fd-util.h"
#include "fileio.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "sd-messages.h"
#include "unit-serialize.h"

static FILE* arg_serialization = NULL;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s\n\n"
               "Sandbox and execute processes.\n\n"
               "  -h --help              Show this help and exit\n"
               "  --version              Print version string and exit\n"
               "  --deserialize=FD       Deserialize process config from FD\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_DESERIALIZE,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'             },
                { "version",      no_argument,       NULL, ARG_VERSION     },
                { "deserialize",  required_argument, NULL, ARG_DESERIALIZE },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_DESERIALIZE: {
                        FILE *f;
                        int fd;

                        fd = parse_fd(optarg);
                        if (fd < 0)
                                return log_error_errno(fd, "Failed to parse serialization fd \"%s\": %m", optarg);

                        (void) fd_cloexec(fd, true);

                        f = fdopen(fd, "r");
                        if (!f)
                                return log_error_errno(errno, "Failed to open serialization fd %d: %m", fd);

                        safe_fclose(arg_serialization);
                        arg_serialization = f;

                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (!arg_serialization)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No serialization fd specified.");

        return 1 /* work to do */;
}

int main(int argc, char *argv[]) {
        int exit_status = EXIT_SUCCESS, r;
        ExecCommand command = {};
        ExecContext context = {};
        ExecParameters params = {
                .stdin_fd         = -EBADF,
                .stdout_fd        = -EBADF,
                .stderr_fd        = -EBADF,
                .exec_fd          = -EBADF,
                .user_lookup_fd   = -EBADF,
                .bpf_outer_map_fd = -EBADF,
        };
        DynamicCreds dynamic_creds = {
        };
        ExecSharedRuntime shared = {
                .netns_storage_socket = PIPE_EBADF,
                .ipcns_storage_socket = PIPE_EBADF,
        };
        ExecRuntime runtime = {
                .shared = &shared,
                .dynamic_creds = &dynamic_creds,
        };
        CGroupContext cgroup_context;
        size_t unit_size = 0;
        Unit *unit = NULL;
        FDSet *fdset = NULL;

        log_setup();

        r = fdset_new_fill(/* filter_cloexec= */ -1, &fdset);
        if (r < 0)
                return log_error_errno(r, "Failed to create fd set: %m");

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = fdset_remove(fdset, fileno(arg_serialization));
        if (r < 0)
                return log_error_errno(r, "Failed to remove serialization fd from fd set: %m");

        /* We don't know what we are going to get, so just pick the max */
        for (size_t i = 0; i < _UNIT_TYPE_MAX; ++i)
                if (unit_vtable[i]->object_size > unit_size)
                        unit_size = unit_vtable[i]->object_size;

        unit = unit_new(NULL, unit_size);
        if (!unit)
                log_oom();

        _cleanup_free_ char *line = NULL;
        r = read_line(arg_serialization, LONG_LINE_MAX, &line);
        if (r <= 0)
                return log_error_errno(r < 0 ? r : -EIO, "Failed to read unit id from serialized state: %m");
        unit->id = strstrip(line);

        r = unit_deserialize(unit, arg_serialization, fdset);
        if (r < 0)
                return log_error_errno(r, "Failed to deserialize unit: %m");

        r = exec_command_deserialize(&command, arg_serialization);
        if (r < 0)
                return log_error_errno(r, "Failed to deserialize ExecCommand: %m");

        r = exec_parameters_deserialize(&params, arg_serialization, fdset);
        if (r < 0)
                return log_error_errno(r, "Failed to deserialize ExecParameters: %m");

        r = exec_runtime_deserialize(&runtime, arg_serialization, fdset);
        if (r < 0)
                return log_error_errno(r, "Failed to deserialize ExecRuntime: %m");

        exec_context_init(&context);

        r = exec_context_deserialize(&context, arg_serialization, fdset);
        if (r < 0)
                return log_error_errno(r, "Failed to deserialize ExecContext: %m");

        cgroup_context_init(&cgroup_context);

        r = exec_cgroup_context_deserialize(&cgroup_context, arg_serialization);
        if (r < 0)
                return log_error_errno(r, "Failed to deserialize CGroupContext: %m");

        arg_serialization = safe_fclose(arg_serialization);
        fdset_close(fdset);

        r = exec_child(unit,
                       &command,
                       &context,
                       &params,
                       &runtime,
                       &cgroup_context,
                       &exit_status);
        if (r < 0) {
                const char *status =
                        exit_status_to_string(exit_status, EXIT_STATUS_LIBC | EXIT_STATUS_SYSTEMD);

                log_unit_struct_errno(unit, LOG_ERR, r,
                                      "MESSAGE_ID=" SD_MESSAGE_SPAWN_FAILED_STR,
                                      LOG_UNIT_INVOCATION_ID(unit),
                                      LOG_UNIT_MESSAGE(unit, "Failed at step %s spawning %s: %m",
                                                       status, command.path),
                                      "EXECUTABLE=%s", command.path);
        }

        return exit_status;
}
