/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "build.h"
#include "bus-object.h"
#include "log.h"
#include "nulstr-util.h"
#include "options.h"
#include "runtime-scope.h"
#include "service-util.h"
#include "string-util.h"

int _service_parse_argv(
                const Verb *verbs,
                const Verb *verbs_end,
                const BusObjectImplementation* const* bus_objects,
                RuntimeScope *runtime_scope,
                int argc, char *argv[]) {

        assert(argc >= 0);
        assert(argv);

        const CommandDescription *cmd = NULL;
        assert_se(_verbs_find_command(verbs, verbs_end, /* name= */ NULL, &cmd));

        /* The COMMAND description must reference the option namespace defined below, and list
         * exactly the option groups matching the features the service supports. Options outside of
         * the listed groups are treated as unknown. */
        assert(streq_ptr(cmd->option_namespace, "service"));
        assert(nulstr_contains(cmd->option_groups, "Options"));
        assert(!!bus_objects == nulstr_contains(cmd->option_groups, "Bus introspection"));
        assert(!!runtime_scope == nulstr_contains(cmd->option_groups, "Runtime scope"));

        OptionParser opts = {
                argc, argv,
                .namespace = "service",
                .option_groups = cmd->option_groups,
        };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("service"): {}

                OPTION_GROUP("Options"): {}

                OPTION_COMMON_HELP:
                        return _command_print_help_full(
                                        verbs, verbs_end,
                                        __start_SYSTEMD_OPTIONS, __stop_SYSTEMD_OPTIONS,
                                        cmd->names,
                                        /* footer_ansi_seq= */ NULL);

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_INTROSPECT_CLI:
                        return _introspect_cli(
                                        verbs, verbs_end,
                                        __start_SYSTEMD_OPTIONS, __stop_SYSTEMD_OPTIONS,
                                        SD_JSON_FORMAT_OFF);

                OPTION_GROUP("Bus introspection"): {}

                OPTION_LONG("bus-introspect", "PATH", "Write D-Bus XML introspection data"):
                        return bus_introspect_implementations(stdout, opts.arg, ASSERT_PTR(bus_objects));

                OPTION_GROUP("Runtime scope"): {}

                OPTION_LONG_DATA("system", NULL, /* data= */ RUNTIME_SCOPE_SYSTEM,
                                 "Start service in system mode"): {}
                OPTION_LONG_DATA("user", NULL, /* data= */ RUNTIME_SCOPE_USER,
                                 "Start service in user mode"):
                        *ASSERT_PTR(runtime_scope) = opts.opt->data;
                        break;
                }

        if (option_parser_get_n_args(&opts) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        return 1; /* Further action */
}
