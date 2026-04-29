/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "build.h"
#include "bus-object.h"
#include "format-table.h"
#include "help-util.h"
#include "log.h"
#include "options.h"
#include "runtime-scope.h"
#include "service-util.h"

static int help(const char *program_path,
                const char *service,
                const char *description,
                bool with_bus_introspect,
                bool with_runtime_scope) {

        static const char* const groups[] = {
                NULL,
                "Bus introspection",
                "Runtime scope",
        };

        _cleanup_(table_unref_many) Table* tables[ELEMENTSOF(groups) + 1] = {};
        bool conds[] = { true, with_bus_introspect, with_runtime_scope };
        int r;

        for (size_t i = 0; i < ELEMENTSOF(groups); i++)
                if (conds[i]) {
                        r = option_parser_get_help_table_group(groups[i], &tables[i]);
                        if (r < 0)
                                return r;
                }

        (void) table_sync_column_widths(0, tables[0], tables[1] ?: tables[2], tables[1] ? tables[2] : NULL);

        help_cmdline("[OPTIONS...]");
        help_abstract(description);

        help_section("Options:");
        for (size_t i = 0; i < ELEMENTSOF(groups); i++)
                if (conds[i]) {
                        r = table_print_or_warn(tables[i]);
                        if (r < 0)
                                return r;
                }

        help_man_page_reference(service, "8");
        return 0; /* No further action */
}

int service_parse_argv(
                const char *service,
                const char *description,
                const BusObjectImplementation* const* bus_objects,
                RuntimeScope *runtime_scope,
                int argc, char *argv[]) {

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION(c, &opts, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help(argv[0],
                                    service,
                                    description,
                                    /* with_bus_introspect= */ bus_objects,
                                    /* with_runtime_scope= */ runtime_scope);

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_GROUP("Bus introspection"): {}

                OPTION_LONG("bus-introspect", "PATH", "Write D-Bus XML introspection data"):
                        /* The option is defined in the shared option table, but it's not supported in this binary,
                         * so we pretend it doesn't exist. */
                        if (!bus_objects)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "This service does not support the --bus-introspect= option.");

                        return bus_introspect_implementations(stdout, opts.arg, bus_objects);

                OPTION_GROUP("Runtime scope"): {}

                OPTION_LONG_DATA("system", NULL, /* data= */ RUNTIME_SCOPE_SYSTEM,
                                 "Start service in system mode"): {}
                OPTION_LONG_DATA("user", NULL, /* data= */ RUNTIME_SCOPE_USER,
                                 "Start service in user mode"):
                        if (!runtime_scope)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "This service does not support the --system/--user options.");

                        *runtime_scope = opts.opt->data;
                        break;
                }

        if (option_parser_get_n_args(&opts) > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        return 1; /* Further action */
}
