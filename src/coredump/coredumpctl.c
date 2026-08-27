/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>

#include "sd-bus.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "coredumpctl.h"
#include "coredumpctl-core.h"
#include "coredumpctl-debugger.h"
#include "coredumpctl-list.h"
#include "dissect-image.h"
#include "dlopen-note.h"
#include "extract-word.h"
#include "glob-util.h"
#include "image-policy.h"
#include "log.h"
#include "logs-show.h"
#include "loop-util.h"
#include "main-func.h"
#include "mount-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "verbs.h"

#define SHORT_BUS_CALL_TIMEOUT_USEC (3 * USEC_PER_SEC)

usec_t arg_since = USEC_INFINITY;
usec_t arg_until = USEC_INFINITY;
const char *arg_field = NULL;
const char *arg_debugger = NULL;
char **arg_debugger_args = NULL;
const char *arg_directory = NULL;
char **arg_file = NULL;
sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
PagerFlags arg_pager_flags = 0;
int arg_legend = true;
size_t arg_rows_max = SIZE_MAX;
const char *arg_output = NULL;
bool arg_reverse = false;
bool arg_quiet = false;
bool arg_all = false;
char *arg_root = NULL;
static char *arg_image = NULL;
static ImagePolicy *arg_image_policy = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_debugger_args, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_file, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);

COMMAND(
        "coredumpctl\0",
        "List or retrieve coredumps from the journal.",
        .man_pages = "coredumpctl(1)\0",
        .pager_flags = &arg_pager_flags,
);

VERB_COMMON_HELP_AUTO_HIDDEN();

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        int r;

        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_LEGEND:
                        arg_legend = false;
                        break;

                OPTION_LONG("debugger", "DEBUGGER", "Use the given debugger"):
                        arg_debugger = opts.arg;
                        break;

                OPTION('A', "debugger-arguments", "…", "Pass the given arguments to the debugger"): {
                        _cleanup_strv_free_ char **l = NULL;
                        r = strv_split_full(&l, opts.arg, WHITESPACE, EXTRACT_UNQUOTE);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse debugger arguments '%s': %m", opts.arg);
                        strv_free_and_replace(arg_debugger_args, l);
                        break;
                }

                OPTION_LONG("file", "PATH", "Use journal file"):
                        r = glob_extend(&arg_file, opts.arg, GLOB_NOCHECK);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add paths: %m");
                        break;

                OPTION('o', "output", "FILE", "Write output to FILE"):
                        if (arg_output)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot set output more than once.");

                        arg_output = opts.arg;
                        break;

                OPTION('S', "since", "DATE", "Only print coredumps since the date"):
                        r = parse_timestamp(opts.arg, &arg_since);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timestamp '%s': %m", opts.arg);
                        break;

                OPTION('U', "until", "DATE", "Only print coredumps until the date"):
                        r = parse_timestamp(opts.arg, &arg_until);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timestamp '%s': %m", opts.arg);
                        break;

                OPTION('F', "field", "FIELD", "List all values a certain field takes"):
                        if (arg_field)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot use --field/-F more than once.");
                        arg_field = opts.arg;
                        break;

                OPTION_SHORT('1', NULL, "Show information about most recent entry only"):
                        arg_rows_max = 1;
                        arg_reverse = true;
                        break;

                OPTION_SHORT('n', "INT", "Show at most this many rows"): {
                        unsigned n;

                        r = safe_atou(opts.arg, &n);
                        if (r < 0 || n < 1)
                                return log_error_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid numeric parameter to -n: %s", opts.arg);

                        arg_rows_max = n;
                        break;
                }

                OPTION('D', "directory", "DIR", "Use journal files from directory"):
                        arg_directory = opts.arg;
                        break;

                OPTION_LONG("root", "PATH", "Operate on an alternate filesystem root"):
                        r = parse_path_argument(opts.arg, false, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image", "PATH", "Operate on disk image as filesystem root"):
                        r = parse_path_argument(opts.arg, false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image-policy", "POLICY", "Specify disk image dissection policy"):
                        r = parse_image_policy_argument(opts.arg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                OPTION('r', "reverse", NULL, "Show the newest entries first"):
                        arg_reverse = true;
                        break;

                OPTION('q', "quiet", NULL, "Do not show info messages and privilege warning"):
                        arg_quiet = true;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("all", NULL, "Look at all journal files instead of local ones"):
                        arg_all = true;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(arg_json_format_flags);
                }

        if (arg_since != USEC_INFINITY && arg_until != USEC_INFINITY &&
            arg_since > arg_until)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--since= must be before --until=.");

        if ((!!arg_directory + !!arg_image + !!arg_root) > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root=, --image= or -D/--directory=, the combination of these options is not supported.");

        *remaining_args = option_parser_get_args(&opts);
        return 1;
}

VERB_SCOPE(, verb_dump_list, "list", "[MATCHES…]", VERB_ANY, VERB_ANY, VERB_DEFAULT,
           "List available coredumps");
VERB_SCOPE(, verb_dump_list, "info", "[MATCHES…]", VERB_ANY, VERB_ANY, 0,
           "Show detailed information about one or more coredumps");
VERB_SCOPE(, verb_dump_core, "dump", "[MATCHES…]", VERB_ANY, VERB_ANY, 0,
           "Print first matching coredump to stdout");
VERB_SCOPE(, verb_run_debug, "debug", "[MATCHES…]", VERB_ANY, VERB_ANY, 0,
           "Start a debugger for the first matching coredump");
VERB_SCOPE(, verb_run_debug, "gdb", "[MATCHES…]", VERB_ANY, VERB_ANY, 0,
           /* help= */ NULL);

static int check_units_active(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int c = 0, r;
        const char *id, *state, *substate;

        if (arg_quiet)
                return false;

        r = sd_bus_default_system(&bus);
        if (r == -ENOENT) {
                log_debug("D-Bus is not running, skipping active unit check");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to acquire bus: %m");

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "ListUnitsByPatterns");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, NULL);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, STRV_MAKE("systemd-coredump@*.service"));
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, SHORT_BUS_CALL_TIMEOUT_USEC, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to check if any systemd-coredump@.service units are running: %s",
                                       bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "(ssssssouso)");
        if (r < 0)
                return bus_log_parse_error(r);

        while ((r = sd_bus_message_read(
                                reply, "(ssssssouso)",
                                &id,  NULL,  NULL,  &state,  &substate,
                                NULL,  NULL,  NULL,  NULL,  NULL)) > 0) {
                bool found = !STR_IN_SET(state, "inactive", "dead", "failed");
                log_debug("Unit %s is %s/%s, %scounting it.", id, state, substate, found ? "" : "not ");
                c += found;
        }
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        return c;
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        char **args = NULL;
        int r, units_active;

        COMPRESS_DEFAULT_NOTE;
        LIBACL_NOTE(recommended);
        LIBBLKID_NOTE(recommended);
        LIBCRYPTO_NOTE(suggested);
        LIBCRYPTSETUP_NOTE(suggested);
        LIBMOUNT_NOTE(recommended);

        setlocale(LC_ALL, "");
        log_setup();

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        journal_browse_prepare();

        units_active = check_units_active(); /* error is treated the same as 0 */

        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                arg_image_policy,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_VALIDATE_OS |
                                DISSECT_IMAGE_ALLOW_USERSPACE_VERITY,
                                &mounted_dir,
                                /* ret_dir_fd= */ NULL,
                                &loop_device);
                if (r < 0)
                        return r;

                arg_root = strdup(mounted_dir);
                if (!arg_root)
                        return log_oom();
        }

        r = dispatch_verb(args, NULL);

        if (units_active > 0)
                printf("%s-- Notice: %d systemd-coredump@.service %s, output may be incomplete.%s\n",
                       ansi_highlight_red(),
                       units_active, units_active == 1 ? "unit is running" : "units are running",
                       ansi_normal());

        return r;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
