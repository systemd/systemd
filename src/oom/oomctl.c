/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-json.h"

#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-message-util.h"
#include "log.h"
#include "main-func.h"
#include "pager.h"
#include "verbs.h"

static PagerFlags arg_pager_flags = 0;

COMMAND(
        "oomctl\0",
        "Manage or inspect the userspace OOM killer.",
        .man_pages = "oomctl.1\0",
        .pager_flags = &arg_pager_flags,
);

VERB_COMMON_HELP_AUTO_HIDDEN("oomctl");

VERB_DEFAULT_NOARG(verb_dump_state, "dump", "Output the current state of systemd-oomd");
static int verb_dump_state(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect system bus: %m");

        pager_open(arg_pager_flags);

        r = bus_call_method(bus, bus_oom_mgr, "DumpByFileDescriptor", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to dump context: %s", bus_error_message(&error, r));

        return bus_message_dump_fd(reply);
}

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help("oomctl");

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static int run(int argc, char* argv[]) {
        int r;

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
