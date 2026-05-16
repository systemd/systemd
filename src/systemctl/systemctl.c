/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>
#include <unistd.h>

#include "argv-util.h"
#include "build.h"
#include "bus-print-properties.h"
#include "bus-util.h"
#include "capsule-util.h"
#include "extract-word.h"
#include "format-table.h"
#include "help-util.h"
#include "image-policy.h"
#include "install.h"
#include "options.h"
#include "output-mode.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "static-destruct.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "systemctl.h"
#include "systemctl-compat-halt.h"
#include "systemctl-compat-shutdown.h"
#include "systemctl-logind.h"
#include "time-util.h"
#include "verbs.h"

char **arg_types = NULL;
char **arg_states = NULL;
char **arg_properties = NULL;
bool arg_all = false;
enum dependency arg_dependency = DEPENDENCY_FORWARD;
const char *_arg_job_mode = NULL;
RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
bool arg_wait = false;
bool arg_no_block = false;
int arg_legend = -1; /* -1: true, unless --quiet is passed, 1: true */
PagerFlags arg_pager_flags = 0;
bool arg_no_wtmp = false;
bool arg_no_sync = false;
bool arg_no_wall = false;
bool arg_no_reload = false;
BusPrintPropertyFlags arg_print_flags = 0;
bool arg_show_types = false;
int arg_check_inhibitors = -1;
bool arg_dry_run = false;
bool arg_quiet = false;
bool arg_verbose = false;
bool arg_no_warn = false;
bool arg_full = false;
bool arg_recursive = false;
bool arg_with_dependencies = false;
bool arg_show_transaction = false;
int arg_force = 0;
bool arg_ask_password = false;
bool arg_runtime = false;
UnitFilePresetMode arg_preset_mode = UNIT_FILE_PRESET_FULL;
char **arg_wall = NULL;
const char *arg_kill_whom = NULL;
int arg_signal = SIGTERM;
int arg_kill_value;
bool arg_kill_value_set = false;
char *arg_root = NULL;
char *arg_image = NULL;
usec_t arg_when = 0;
bool arg_stdin = false;
const char *arg_reboot_argument = NULL;
char *arg_kernel_cmdline = NULL;
enum action arg_action = ACTION_SYSTEMCTL;
BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
const char *arg_host = NULL;
unsigned arg_lines = 10;
OutputMode arg_output = OUTPUT_SHORT;
bool arg_plain = false;
bool arg_firmware_setup = false;
usec_t arg_boot_loader_menu = USEC_INFINITY;
const char *arg_boot_loader_entry = NULL;
bool arg_now = false;
bool arg_jobs_before = false;
bool arg_jobs_after = false;
char **arg_clean_what = NULL;
TimestampStyle arg_timestamp_style = TIMESTAMP_PRETTY;
bool arg_read_only = false;
bool arg_mkdir = false;
bool arg_marked = false;
const char *arg_drop_in = NULL;
ImagePolicy *arg_image_policy = NULL;
char *arg_kill_subgroup = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_types, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_states, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_properties, strv_freep);
STATIC_DESTRUCTOR_REGISTER(_arg_job_mode, unsetp);
STATIC_DESTRUCTOR_REGISTER(arg_wall, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_kill_whom, unsetp);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_reboot_argument, unsetp);
STATIC_DESTRUCTOR_REGISTER(arg_kernel_cmdline, freep);
STATIC_DESTRUCTOR_REGISTER(arg_host, unsetp);
STATIC_DESTRUCTOR_REGISTER(arg_boot_loader_entry, unsetp);
STATIC_DESTRUCTOR_REGISTER(arg_clean_what, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_drop_in, unsetp);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);
STATIC_DESTRUCTOR_REGISTER(arg_kill_subgroup, freep);

static int systemctl_help(void) {
        static const char *const vgroups[] = {
                "Unit Commands",
                "Unit File Commands",
                "Machine Commands",
                "Job Commands",
                "Environment Commands",
                "Manager State Commands",
                "System Commands",
        };

        Table *vtables[ELEMENTSOF(vgroups)] = {};
        CLEANUP_ELEMENTS(vtables, table_unref_array_clear);
        _cleanup_(table_unrefp) Table *options_table = NULL;
        int r;

        for (size_t i = 0; i < ELEMENTSOF(vgroups); i++) {
                r = verbs_get_help_table_group(vgroups[i], &vtables[i]);
                if (r < 0)
                        return r;
        }

        r = option_parser_get_help_table_ns("systemctl", &options_table);
        if (r < 0)
                return r;

        assert_cc(ELEMENTSOF(vtables) == 7);
        (void) table_sync_column_widths(0, options_table,
                                        vtables[0], vtables[1], vtables[2], vtables[3],
                                        vtables[4], vtables[5], vtables[6]);

        pager_open(arg_pager_flags);

        help_cmdline("[OPTIONS…] COMMAND …");
        help_abstract("Query or send control commands to the system manager.");

        for (size_t i = 0; i < ELEMENTSOF(vgroups); i++) {
                help_section(vgroups[i]);
                r = table_print_or_warn(vtables[i]);
                if (r < 0)
                        return r;
        }

        help_section("Options");
        r = table_print_or_warn(options_table);
        if (r < 0)
                return r;

        help_man_page_reference("systemctl", "1");

        return 0;
}

static int parse_property_argument(const char *value, char ***properties) {
        int r;

        assert(value);
        assert(properties);

        if (isempty(value) && !*properties) {
                /* Make sure that if the empty property list was specified, we won't show any properties. */
                *properties = strv_new(NULL);
                if (!*properties)
                        return log_oom();
        } else
                for (const char *p = value;;) {
                        _cleanup_free_ char *prop = NULL;

                        r = extract_first_word(&p, &prop, ",", /* flags= */ 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse property: '%s'", value);
                        if (r == 0)
                                break;

                        if (strv_consume(properties, TAKE_PTR(prop)) < 0)
                                return log_oom();
                }

        return 0;
}

static int help_states(void) {
        if (arg_legend != 0)
                puts("Available unit load states:");
        DUMP_STRING_TABLE(unit_load_state, UnitLoadState, _UNIT_LOAD_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable unit active states:");
        DUMP_STRING_TABLE(unit_active_state, UnitActiveState, _UNIT_ACTIVE_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable unit file states:");
        DUMP_STRING_TABLE(unit_file_state, UnitFileState, _UNIT_FILE_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable automount unit substates:");
        DUMP_STRING_TABLE(automount_state, AutomountState, _AUTOMOUNT_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable device unit substates:");
        DUMP_STRING_TABLE(device_state, DeviceState, _DEVICE_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable mount unit substates:");
        DUMP_STRING_TABLE(mount_state, MountState, _MOUNT_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable path unit substates:");
        DUMP_STRING_TABLE(path_state, PathState, _PATH_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable scope unit substates:");
        DUMP_STRING_TABLE(scope_state, ScopeState, _SCOPE_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable service unit substates:");
        DUMP_STRING_TABLE(service_state, ServiceState, _SERVICE_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable slice unit substates:");
        DUMP_STRING_TABLE(slice_state, SliceState, _SLICE_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable socket unit substates:");
        DUMP_STRING_TABLE(socket_state, SocketState, _SOCKET_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable swap unit substates:");
        DUMP_STRING_TABLE(swap_state, SwapState, _SWAP_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable target unit substates:");
        DUMP_STRING_TABLE(target_state, TargetState, _TARGET_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable timer unit substates:");
        return DUMP_STRING_TABLE(timer_state, TimerState, _TIMER_STATE_MAX);
}

static int parse_states_argument(const char *value, char ***states) {
        int r;

        assert(value);
        assert(states);

        if (isempty(value)) {
                /* reset the setting */
                *states = strv_free(*states);
                return 1;
        }

        for (const char *p = value;;) {
                _cleanup_free_ char *s = NULL;

                r = extract_first_word(&p, &s, ",", /* flags= */ 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse --state=: %m");
                if (r == 0)
                        break;

                if (streq(s, "help"))
                        return help_states();

                if (strv_consume(states, TAKE_PTR(s)) < 0)
                        return log_oom();
        }

        return 1;
}

static int help_types(void) {
        if (arg_legend != 0)
                puts("Available unit types:");

        return DUMP_STRING_TABLE(unit_type, UnitType, _UNIT_TYPE_MAX);
}

static int parse_types_argument(const char *value, char ***types, char ***states) {
        int r;

        assert(value);
        assert(types);
        assert(states);

        if (isempty(value)) {
                /* reset the setting */
                *types = strv_free(*types);
                return 1;
        }

        for (const char *p = value;;) {
                _cleanup_free_ char *type = NULL;

                r = extract_first_word(&p, &type, ",", /* flags= */ 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse -t/--type=: %m");
                if (r == 0)
                        break;

                if (streq(type, "help"))
                        return help_types();

                if (unit_type_from_string(type) >= 0) {
                        if (strv_consume(types, TAKE_PTR(type)) < 0)
                                return log_oom();
                        continue;
                }

                /* It's much nicer to use --state= for load states, but let's support this in
                 * --types= too for compatibility with old versions */
                if (unit_load_state_from_string(type) >= 0) {
                        if (strv_consume(states, TAKE_PTR(type)) < 0)
                                return log_oom();
                        continue;
                }

                log_error("Unknown unit type or load state '%s'.", type);
                return log_info_errno(SYNTHETIC_ERRNO(EINVAL),
                                      "Use -t help to see a list of allowed values.");
        }

        return 1;
}

static int parse_what_argument(const char *value, char ***clean_what) {
        int r;

        assert(value);
        assert(clean_what);

        if (isempty(value)) {
                /* reset the setting */
                *clean_what = strv_free(*clean_what);
                return 1;
        }

        for (const char *p = value;;) {
                _cleanup_free_ char *k = NULL;

                r = extract_first_word(&p, &k, ",", /* flags= */ 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse --what=: %m");
                if (r == 0)
                        break;

                if (streq(k, "help")) {
                        puts("runtime\n"
                             "state\n"
                             "cache\n"
                             "logs\n"
                             "configuration\n"
                             "fdstore\n"
                             "all");
                        return 0;
                }

                r = strv_consume(clean_what, TAKE_PTR(k));
                if (r < 0)
                        return log_oom();
        }

        return 1;
}

static int systemctl_parse_argv(int argc, char *argv[], int log_level_shift, char ***remaining_args) {
        int r;

        assert(argc >= 0);
        assert(argv);

        /* We default to allowing interactive authorization only in systemctl (not in the legacy commands) */
        arg_ask_password = true;

        OptionParser opts = {
                argc, argv,
                .namespace = "systemctl",
                .log_level_shift = log_level_shift,
        };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("systemctl"): {}

                OPTION_COMMON_HELP:
                        return systemctl_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("system", NULL, "Connect to the system service manager"):
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                OPTION_LONG("user", NULL, "Connect to the user service manager"):
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                OPTION('C', "capsule", "NAME", "Connect to service manager of specified capsule"):
                        r = capsule_name_is_valid(opts.arg);
                        if (r < 0)
                                return log_error_errno(r, "Unable to validate capsule name '%s': %m", opts.arg);
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid capsule name: %s", opts.arg);

                        arg_host = opts.arg;
                        arg_transport = BUS_TRANSPORT_CAPSULE;
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                OPTION_COMMON_HOST:
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = opts.arg;
                        break;

                OPTION_COMMON_MACHINE:
                        r = parse_machine_argument(opts.arg, &arg_host, &arg_transport);
                        if (r < 0)
                                return r;
                        break;

                OPTION('t', "type", "TYPE", "List units of a particular type"):
                        r = parse_types_argument(opts.arg, &arg_types, &arg_states);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("state", "STATE", "List units with particular LOAD or SUB or ACTIVE state"):
                        r = parse_states_argument(opts.arg, &arg_states);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("failed", NULL, "Shortcut for --state=failed"):
                        if (strv_extend(&arg_states, "failed") < 0)
                                return log_oom();
                        break;

                OPTION('p', "property", "NAME", "Show only properties by this name"): {}
                OPTION_SHORT('P', "NAME", "Equivalent to --value --property=NAME"):
                        r = parse_property_argument(opts.arg, &arg_properties);
                        if (r < 0)
                                return r;

                        /* If the user asked for a particular property, show it, even if it is empty. */
                        SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_SHOW_EMPTY, true);

                        if (opts.opt->short_code == 'P')
                                SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_ONLY_VALUE, true);

                        break;

                OPTION('a', "all", NULL,
                       "Show all properties/all units currently in memory, including dead/empty ones. "
                       "To list all units installed on the system, use 'list-unit-files' instead"):
                        SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_SHOW_EMPTY, true);
                        arg_all = true;
                        break;

                OPTION('l', "full", NULL, "Don't ellipsize unit names on output"):
                        arg_full = true;
                        break;

                OPTION('r', "recursive", NULL, "Show unit list of host and local containers"):
                        if (geteuid() != 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                                       "--recursive requires root privileges");

                        arg_recursive = true;
                        break;

                OPTION_LONG("reverse", NULL, "Show reverse dependencies with 'list-dependencies'"):
                        arg_dependency = DEPENDENCY_REVERSE;
                        break;

                OPTION_LONG("before", NULL, "Show units ordered before with 'list-dependencies'"):
                        arg_dependency = DEPENDENCY_BEFORE;
                        arg_jobs_before = true;
                        break;

                OPTION_LONG("after", NULL, "Show units ordered after with 'list-dependencies'"):
                        arg_dependency = DEPENDENCY_AFTER;
                        arg_jobs_after = true;
                        break;

                OPTION_LONG("with-dependencies", NULL,
                            "Show unit dependencies with 'status', 'cat', 'list-units', and 'list-unit-files'"):
                        arg_with_dependencies = true;
                        break;

                OPTION_LONG("job-mode", "MODE",
                            "Specify how to deal with already queued jobs, when queueing a new job"):
                        _arg_job_mode = opts.arg;
                        break;

                OPTION('T', "show-transaction", NULL, "When enqueuing a unit job, show full transaction"):
                        arg_show_transaction = true;
                        break;

                OPTION_LONG("show-types", NULL, "When showing sockets, explicitly show their type"):
                        arg_show_types = true;
                        break;

                OPTION_LONG("value", NULL, "When showing properties, only print the value"):
                        SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_ONLY_VALUE, true);
                        break;

                OPTION_LONG("check-inhibitors", "MODE",
                            "Whether to check inhibitors before shutting down, sleeping, or hibernating"):
                        r = parse_tristate_argument_with_auto("--check-inhibitors=", opts.arg, &arg_check_inhibitors);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("ignore-inhibitors", NULL, /* help= */ NULL): {}

                OPTION_SHORT('i', NULL, "Shortcut for --check-inhibitors=no"):
                        arg_check_inhibitors = 0;
                        break;

                OPTION('s', "signal", "SIGNAL", "Which signal to send"):
                        r = parse_signal_argument(opts.arg, &arg_signal);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("kill-whom", "WHOM", "Whom to send signal to"):
                        arg_kill_whom = opts.arg;
                        break;

                OPTION_LONG("kill-value", "INT", "Signal value to enqueue"): {
                        unsigned u;

                        if (isempty(opts.arg)) {
                                arg_kill_value_set = false;
                                return 0;
                        }

                        /* First, try to parse unsigned, so that we can support the prefixes 0x, 0o, 0b */
                        r = safe_atou_full(opts.arg, 0, &u);
                        if (r < 0)
                                /* If this didn't work, try as signed integer, without those prefixes */
                                r = safe_atoi(opts.arg, &arg_kill_value);
                        else if (u > INT_MAX)
                                r = -ERANGE;
                        else
                                arg_kill_value = (int) u;
                        if (r < 0)
                                return log_error_errno(r, "Unable to parse signal queue value: %s", opts.arg);

                        arg_kill_value_set = true;
                        break;
                }

                OPTION_LONG("kill-subgroup", "PATH", "Send signal to sub-control group only"): {
                        if (empty_or_root(opts.arg)) {
                                arg_kill_subgroup = mfree(arg_kill_subgroup);
                                break;
                        }

                        _cleanup_free_ char *p = NULL;
                        if (path_simplify_alloc(opts.arg, &p) < 0)
                                return log_oom();

                        if (!path_is_safe(p))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Control group sub-path '%s' is not valid.", p);

                        free_and_replace(arg_kill_subgroup, p);
                        break;
                }

                OPTION_LONG("what", "RESOURCES", "Which types of resources to remove"):
                        r = parse_what_argument(opts.arg, &arg_clean_what);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("now", NULL, "Start or stop unit after enabling or disabling it"):
                        arg_now = true;
                        break;

                OPTION_LONG("dry-run", NULL,
                            "Only print what would be done. Currently supported by verbs: halt, poweroff, "
                            "reboot, kexec, soft-reboot, suspend, hibernate, suspend-then-hibernate, "
                            "hybrid-sleep, default, rescue, emergency, and exit."):
                        arg_dry_run = true;
                        break;

                OPTION('q', "quiet", NULL, "Suppress output"):
                        arg_quiet = true;

                        if (arg_legend < 0)
                                arg_legend = false;

                        break;

                OPTION('v', "verbose", NULL, "Show unit logs while executing operation"):
                        arg_verbose = true;
                        break;

                OPTION_LONG("no-warn", NULL, "Suppress several warnings shown by default"):
                        arg_no_warn = true;
                        break;

                OPTION_LONG("wait", NULL,
                            "For (re)start, wait until service stopped again. "
                            "For is-system-running, wait until startup is completed. "
                            "For kill, wait until service stopped."):
                        arg_wait = true;
                        break;

                OPTION_LONG("no-block", NULL, "Do not wait until operation finished"):
                        arg_no_block = true;
                        break;

                OPTION_LONG("no-wall", NULL, "Don't send wall message before halt/power-off/reboot"):
                        arg_no_wall = true;
                        break;

                OPTION_LONG("message", "MESSAGE", "Specify human-readable reason for system shutdown"):
                        if (strv_extend(&arg_wall, opts.arg) < 0)
                                return log_oom();
                        break;

                OPTION_LONG("no-reload", NULL, "Don't reload daemon after en-/dis-abling unit files"):
                        arg_no_reload = true;
                        break;

                OPTION_LONG("legend", "BOOL", "Enable/disable the legend (column headers and hints)"):
                        r = parse_boolean_argument("--legend", opts.arg, NULL);
                        if (r < 0)
                                return r;
                        arg_legend = r;
                        break;

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                OPTION_LONG("global", NULL, "Edit/enable/disable/mask default user unit files globally"):
                        arg_runtime_scope = RUNTIME_SCOPE_GLOBAL;
                        break;

                OPTION_LONG("runtime", NULL,
                            "Edit/enable/disable/mask unit files temporarily until next reboot"):
                        arg_runtime = true;
                        break;

                OPTION('f', "force", NULL,
                       "When enabling unit files, override existing symlinks. "
                       "When shutting down, execute action immediately."):
                        arg_force++;
                        break;

                OPTION_LONG("preset-mode", "MODE", "Apply only enable, only disable, or all presets"):
                        if (streq(opts.arg, "help"))
                                return DUMP_STRING_TABLE(unit_file_preset_mode, UnitFilePresetMode, _UNIT_FILE_PRESET_MODE_MAX);

                        arg_preset_mode = unit_file_preset_mode_from_string(opts.arg);
                        if (arg_preset_mode < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse preset mode: %s.", opts.arg);

                        break;

                OPTION_LONG("root", "PATH",
                            "Edit/enable/disable/mask unit files in the specified root directory"):
                        r = parse_path_argument(opts.arg, false, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image", "PATH",
                            "Edit/enable/disable/mask unit files in the specified disk image"):
                        r = parse_path_argument(opts.arg, false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image-policy", "POLICY", "Specify disk image dissection policy"):
                        r = parse_image_policy_argument(opts.arg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                OPTION('n', "lines", "INTEGER", "Number of journal entries to show"):
                        if (safe_atou(opts.arg, &arg_lines) < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse lines '%s'",
                                                       opts.arg);
                        break;

                OPTION('o', "output", "STRING",
                       "Change journal output mode (short, short-precise, short-iso, short-iso-precise, "
                       "short-full, short-monotonic, short-unix, short-delta, verbose, export, json, "
                       "json-pretty, json-sse, cat)"):
                        if (streq(opts.arg, "help"))
                                return DUMP_STRING_TABLE(output_mode, OutputMode, _OUTPUT_MODE_MAX);

                        arg_output = output_mode_from_string(opts.arg);
                        if (arg_output < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown output '%s'.",
                                                       opts.arg);

                        if (OUTPUT_MODE_IS_JSON(arg_output)) {
                                arg_legend = false;
                                arg_plain = true;
                        }
                        break;

                OPTION_LONG("firmware-setup", NULL, "Tell the firmware to show the setup menu on next boot"):
                        arg_firmware_setup = true;
                        break;

                OPTION_LONG("boot-loader-menu", "TIME", "Boot into boot loader menu on next boot"):
                        r = parse_sec(opts.arg, &arg_boot_loader_menu);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --boot-loader-menu= argument '%s': %m", opts.arg);

                        break;

                OPTION_LONG("boot-loader-entry", "NAME",
                            "Boot into a specific boot loader entry on next boot"):
                        if (streq(opts.arg, "help")) { /* Yes, this means, "help" is not a valid boot loader entry name we can deal with */
                                r = help_boot_loader_entry();
                                if (r < 0)
                                        return r;

                                return 0;
                        }

                        arg_boot_loader_entry = empty_to_null(opts.arg);
                        break;

                OPTION_LONG("reboot-argument", "ARG", "Specify argument string to pass to reboot()"):
                        arg_reboot_argument = opts.arg;
                        break;

                OPTION_LONG("kernel-cmdline", "CMDLINE",
                            "Append to the kernel command line when loading the kernel "
                            "from the booted boot loader entry"):
                        if (isempty(opts.arg)) {
                                arg_kernel_cmdline = mfree(arg_kernel_cmdline);
                                break;
                        }

                        if (!string_is_safe(opts.arg, STRING_ALLOW_GLOBS|STRING_ALLOW_BACKSLASHES|STRING_ALLOW_QUOTES))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--kernel-cmdline= argument contains invalid characters: %s", opts.arg);

                        r = free_and_strdup_warn(&arg_kernel_cmdline, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("plain", NULL, "Print unit dependencies as a list instead of a tree"):
                        arg_plain = true;
                        break;

                OPTION_LONG("timestamp", "FORMAT",
                            "Change format of printed timestamps (pretty, unix, us, utc, us+utc)"):
                        if (streq(opts.arg, "help"))
                                return DUMP_STRING_TABLE(timestamp_style, TimestampStyle, _TIMESTAMP_STYLE_MAX);

                        arg_timestamp_style = timestamp_style_from_string(opts.arg);
                        if (arg_timestamp_style < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid value: %s.", opts.arg);

                        break;

                OPTION_LONG("read-only", NULL, "Create read-only bind mount"):
                        arg_read_only = true;
                        break;

                OPTION_LONG("mkdir", NULL, "Create directory before mounting, if missing"):
                        arg_mkdir = true;
                        break;

                OPTION_LONG("marked", NULL, "Restart/reload previously marked units"):
                        arg_marked = true;
                        break;

                OPTION_LONG("drop-in", "NAME", "Edit unit files using the specified drop-in file name"):
                        arg_drop_in = opts.arg;
                        break;

                OPTION_LONG("when", "TIME",
                            "Schedule halt/power-off/reboot/kexec action after a certain timestamp"):
                        if (streq(opts.arg, "show")) {
                                arg_action = ACTION_SYSTEMCTL_SHOW_SHUTDOWN;
                                return 1;
                        }

                        if (STR_IN_SET(opts.arg, "", "cancel")) {
                                arg_action = ACTION_CANCEL_SHUTDOWN;
                                return 1;
                        }

                        if (streq(opts.arg, "auto")) {
                                arg_when = USEC_INFINITY; /* logind chooses on server side */
                                break;
                        }

                        r = parse_timestamp(opts.arg, &arg_when);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --when= argument '%s': %m", opts.arg);

                        if (!timestamp_is_set(arg_when))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid timestamp '%s' specified for --when=.", opts.arg);

                        break;

                OPTION_LONG("stdin", NULL, "Read new contents of edited file from stdin"):
                        arg_stdin = true;
                        break;

                /* Compatibility-only options, not shown in --help. */
                OPTION_LONG("fail", NULL, /* help= */ NULL):
                        _arg_job_mode = "fail";
                        break;

                OPTION_LONG("irreversible", NULL, /* help= */ NULL):
                        _arg_job_mode = "replace-irreversibly";
                        break;

                OPTION_LONG("ignore-dependencies", NULL, /* help= */ NULL):
                        _arg_job_mode = "ignore-dependencies";
                        break;

                OPTION_LONG("no-legend", NULL, /* help= */ NULL):
                        arg_legend = false;
                        break;

                OPTION_SHORT_FLAGS(OPTION_OPTIONAL_ARG, '.', "ARG", /* help= */ NULL):
                        /* Output an error mimicking getopt, and print a hint afterwards */
                        log_error("%s: invalid option -- '.'", program_invocation_name);
                        log_notice("Hint: to specify units starting with a dash, use \"--\":\n"
                                   "      %s [OPTIONS…] COMMAND -- -.%s …",
                                   program_invocation_name, opts.arg ?: "mount");
                        return -EINVAL;
                }

        /* If we are in --user mode, there's no point in talking to PolicyKit or the infra to query system
         * passwords */
        if (arg_runtime_scope != RUNTIME_SCOPE_SYSTEM)
                arg_ask_password = false;

        if (arg_transport == BUS_TRANSPORT_REMOTE && arg_runtime_scope != RUNTIME_SCOPE_SYSTEM)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Cannot access user instance remotely.");

        if (arg_transport == BUS_TRANSPORT_CAPSULE && arg_runtime_scope != RUNTIME_SCOPE_USER)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Cannot access system instance with --capsule=/-C.");

        if (arg_wait && arg_no_block)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--wait may not be combined with --no-block.");

        char **args = option_parser_get_args(&opts);
        size_t n_args = option_parser_get_n_args(&opts);

        bool do_reload_or_restart = streq_ptr(args[0], "reload-or-restart");
        if (arg_marked) {
                if (!do_reload_or_restart)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--marked may only be used with 'reload-or-restart'.");
                if (n_args > 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "No additional arguments allowed with 'reload-or-restart --marked'.");

        } else if (do_reload_or_restart) {
                if (n_args <= 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "List of units to restart/reload is required.");
        }

        if (arg_image && arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Please specify either --root= or --image=, the combination of both is not supported.");

        if (remaining_args)
                *remaining_args = args;
        return 1;
}

int systemctl_dispatch_parse_argv(int argc, char *argv[], int log_level_shift, char ***remaining_args) {
        assert(argc >= 0);
        assert(argv);

        if (invoked_as(argv, "halt")) {
                arg_action = ACTION_HALT;
                return halt_parse_argv(argc, argv, log_level_shift);

        } else if (invoked_as(argv, "poweroff")) {
                arg_action = ACTION_POWEROFF;
                return halt_parse_argv(argc, argv, log_level_shift);

        } else if (invoked_as(argv, "reboot")) {
                arg_action = ACTION_REBOOT;
                return halt_parse_argv(argc, argv, log_level_shift);

        } else if (invoked_as(argv, "shutdown")) {
                arg_action = ACTION_POWEROFF;
                return shutdown_parse_argv(argc, argv, log_level_shift);

        } else {
                arg_action = ACTION_SYSTEMCTL;
                return systemctl_parse_argv(argc, argv, log_level_shift, remaining_args);
        }
}

VERB_GROUP("Unit Commands");

VERB_SCOPE(, verb_list_units,        "list-units",       "[PATTERN…]", VERB_ANY, VERB_ANY, VERB_DEFAULT|VERB_ONLINE_ONLY,
           "List units currently in memory");
VERB_SCOPE(, verb_list_automounts,   "list-automounts",  "[PATTERN…]", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "List automount units currently in memory, ordered by path");
VERB_SCOPE(, verb_list_paths,        "list-paths",       "[PATTERN…]", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "List path units currently in memory, ordered by path");
VERB_SCOPE(, verb_list_sockets,      "list-sockets",     "[PATTERN…]", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "List socket units currently in memory, ordered by address");
VERB_SCOPE(, verb_list_timers,       "list-timers",      "[PATTERN…]", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "List timer units currently in memory, ordered by next elapse");
VERB_SCOPE(, verb_is_active,         "is-active",        "PATTERN…",   2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Check whether units are active");
VERB_SCOPE(, verb_is_failed,         "is-failed",        "[PATTERN…]", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "Check whether units are failed or system is in degraded state");
VERB_SCOPE(, verb_show,              "status",           "[PATTERN…|PID…]", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "Show runtime status of one or more units");
VERB_SCOPE(, verb_show,              "show",             "[PATTERN…|JOB…]", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "Show properties of one or more units/jobs or the manager");
VERB_SCOPE(, verb_cat,               "cat",              "PATTERN…",   2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Show files and drop-ins of specified units");
VERB_SCOPE(, verb_show,              "help",             "PATTERN…|PID…", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "Show manual for one or more units");
VERB_SCOPE(, verb_list_dependencies, "list-dependencies", "[UNIT…]",   VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "Recursively show units which are required or wanted by the units "
           "or by which those units are required or wanted");
VERB_SCOPE(, verb_start,             "start",            "UNIT…",      2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Start (activate) one or more units");
VERB_SCOPE(, verb_start,             "stop",             "UNIT…",      2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Stop (deactivate) one or more units");
VERB_SCOPE(, verb_start,             "reload",           "UNIT…",      2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Reload one or more units");
VERB_SCOPE(, verb_start,             "restart",          "UNIT…",      2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Start or restart one or more units");
VERB_SCOPE(, verb_start,             "try-restart",      "UNIT…",      2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Restart one or more units if active");
VERB_SCOPE(, verb_start,             "enqueue-marked",   NULL,         1,        1,        VERB_ONLINE_ONLY,
           "Enqueue jobs for all marked units");
VERB_SCOPE(, verb_start,             "reload-or-restart", "UNIT…",     VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "Reload one or more units if possible, otherwise start or restart");
VERB_SCOPE(, verb_start,             "try-reload-or-restart", "UNIT…", 2,        VERB_ANY, VERB_ONLINE_ONLY,
           "If active, reload one or more units, if supported, otherwise restart");
VERB_SCOPE(, verb_start,             "isolate",          "UNIT",       2,        2,        VERB_ONLINE_ONLY,
           "Start one unit and stop all others");
VERB_SCOPE(, verb_kill,              "kill",             "UNIT…",      2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Send signal to processes of a unit");
VERB_SCOPE(, verb_clean_or_freeze,   "clean",            "UNIT…",      2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Clean runtime, cache, state, logs or configuration of unit");
VERB_SCOPE(, verb_clean_or_freeze,   "freeze",           "PATTERN…",   2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Freeze execution of unit processes");
VERB_SCOPE(, verb_clean_or_freeze,   "thaw",             "PATTERN…",   2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Resume execution of a frozen unit");
VERB_SCOPE(, verb_set_property,      "set-property",     "UNIT PROPERTY=VALUE…", 3, VERB_ANY, VERB_ONLINE_ONLY,
           "Sets one or more properties of a unit");
VERB_SCOPE(, verb_bind,              "bind",             "UNIT PATH [PATH]",     3, 4, VERB_ONLINE_ONLY,
           "Bind-mount a path from the host into a unit's namespace");
VERB_SCOPE(, verb_mount_image,       "mount-image",      "UNIT PATH [PATH [OPTS]]", 4, 5, VERB_ONLINE_ONLY,
           "Mount an image from the host into a unit's namespace");
VERB_SCOPE(, verb_service_log_setting, "service-log-level", "SERVICE [LEVEL]",   2, 3, VERB_ONLINE_ONLY,
           "Get/set logging threshold for service");
VERB_SCOPE(, verb_service_log_setting, "service-log-target", "SERVICE [TARGET]", 2, 3, VERB_ONLINE_ONLY,
           "Get/set logging target for service");
VERB_SCOPE(, verb_reset_failed,      "reset-failed",     "[PATTERN…]", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "Reset failed state for all, one, or more units");
VERB_SCOPE(, verb_whoami,            "whoami",           "[PID…]",     VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "Return unit caller or specified PIDs are part of");

VERB_GROUP("Unit File Commands");

VERB_SCOPE(, verb_list_unit_files,   "list-unit-files",  "[PATTERN…]", VERB_ANY, VERB_ANY, 0,
           "List installed unit files");
VERB_SCOPE(, verb_enable,            "enable",           "[UNIT…|PATH…]", 2,     VERB_ANY, 0,
           "Enable one or more unit files");
VERB_SCOPE(, verb_enable,            "disable",          "UNIT…",      2,        VERB_ANY, 0,
           "Disable one or more unit files");
VERB_SCOPE(, verb_enable,            "reenable",         "UNIT…",      2,        VERB_ANY, 0,
           "Reenable one or more unit files");
VERB_SCOPE(, verb_enable,            "preset",           "UNIT…",      2,        VERB_ANY, 0,
           "Enable/disable one or more unit files based on preset configuration");
VERB_SCOPE(, verb_preset_all,        "preset-all",       NULL,         VERB_ANY, 1,        0,
           "Enable/disable all unit files based on preset configuration");
VERB_SCOPE(, verb_is_enabled,        "is-enabled",       "UNIT…",      2,        VERB_ANY, 0,
           "Check whether unit files are enabled");
VERB_SCOPE(, verb_enable,            "mask",             "UNIT…",      2,        VERB_ANY, 0,
           "Mask one or more units");
VERB_SCOPE(, verb_enable,            "unmask",           "UNIT…",      2,        VERB_ANY, 0,
           "Unmask one or more units");
VERB_SCOPE(, verb_enable,            "link",             "PATH…",      2,        VERB_ANY, 0,
           "Link one or more units files into the search path");
VERB_SCOPE(, verb_enable,            "revert",           "UNIT…",      2,        VERB_ANY, 0,
           "Revert one or more unit files to vendor version");
VERB_SCOPE(, verb_add_dependency,    "add-wants",        "TARGET UNIT…", 3,      VERB_ANY, 0,
           "Add 'Wants' dependency for the target on specified one or more units");
VERB_SCOPE(, verb_add_dependency,    "add-requires",     "TARGET UNIT…", 3,      VERB_ANY, 0,
           "Add 'Requires' dependency for the target on specified one or more units");
VERB_SCOPE(, verb_edit,              "edit",             "UNIT…",      2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Edit one or more unit files");
VERB_SCOPE(, verb_get_default,       "get-default",      NULL,         VERB_ANY, 1,        0,
           "Get the name of the default target");
VERB_SCOPE(, verb_set_default,       "set-default",      "TARGET",     2,        2,        0,
           "Set the default target");

VERB_GROUP("Machine Commands");

VERB_SCOPE(, verb_list_machines,     "list-machines",    "[PATTERN…]", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "List local containers and host");

VERB_GROUP("Job Commands");

VERB_SCOPE(, verb_list_jobs,         "list-jobs",        "[PATTERN…]", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "List jobs");
VERB_SCOPE(, verb_cancel,            "cancel",           "[JOB…]",     VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "Cancel all, one, or more jobs");

VERB_GROUP("Environment Commands");

VERB_SCOPE(, verb_show_environment,  "show-environment", NULL,         VERB_ANY, 1,        VERB_ONLINE_ONLY,
           "Dump environment");
VERB_SCOPE(, verb_set_environment,   "set-environment",  "VARIABLE=VALUE…", 2,   VERB_ANY, VERB_ONLINE_ONLY,
           "Set one or more environment variables");
VERB_SCOPE(, verb_set_environment,   "unset-environment", "VARIABLE…", 2,        VERB_ANY, VERB_ONLINE_ONLY,
           "Unset one or more environment variables");
VERB_SCOPE(, verb_import_environment, "import-environment", "VARIABLE…", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "Import all or some environment variables");

VERB_GROUP("Manager State Commands");

VERB_SCOPE(, verb_daemon_reload,     "daemon-reload",    NULL,         1,        1,        VERB_ONLINE_ONLY,
           "Reload systemd manager configuration");
VERB_SCOPE(, verb_daemon_reload,     "daemon-reexec",    NULL,         1,        1,        VERB_ONLINE_ONLY,
           "Reexecute systemd manager");
VERB_SCOPE(, verb_log_setting,       "log-level",        "[LEVEL]",    VERB_ANY, 2,        VERB_ONLINE_ONLY,
           "Get/set logging threshold for manager");
VERB_SCOPE(, verb_log_setting,       "log-target",       "[TARGET]",   VERB_ANY, 2,        VERB_ONLINE_ONLY,
           "Get/set logging target for manager");
VERB_SCOPE(, verb_service_watchdogs, "service-watchdogs", "[BOOL]",    VERB_ANY, 2,        VERB_ONLINE_ONLY,
           "Get/set service watchdog state");

VERB_GROUP("System Commands");

VERB_SCOPE(, verb_is_system_running, "is-system-running", NULL,        VERB_ANY, 1,        0,
           "Check whether system is fully running");
VERB_SCOPE(, verb_start_special,     "default",          NULL,         VERB_ANY, 1,        VERB_ONLINE_ONLY,
           "Enter system default mode");
VERB_SCOPE(, verb_start_system_special, "rescue",        NULL,         VERB_ANY, 1,        VERB_ONLINE_ONLY,
           "Enter system rescue mode");
VERB_SCOPE(, verb_start_system_special, "emergency",     NULL,         VERB_ANY, 1,        VERB_ONLINE_ONLY,
           "Enter system emergency mode");
VERB_SCOPE(, verb_start_system_special, "halt",          NULL,         VERB_ANY, 1,        VERB_ONLINE_ONLY,
           "Shut down and halt the system");
VERB_SCOPE(, verb_start_system_special, "poweroff",      NULL,         VERB_ANY, 1,        VERB_ONLINE_ONLY,
           "Shut down and power-off the system");
VERB_SCOPE(, verb_start_system_special, "reboot",        NULL,         VERB_ANY, 1,        VERB_ONLINE_ONLY,
           "Shut down and reboot the system");
VERB_SCOPE(, verb_start_system_special, "kexec",         NULL,         VERB_ANY, 1,        VERB_ONLINE_ONLY,
           "Shut down and reboot the system with kexec");
VERB_SCOPE(, verb_start_system_special, "soft-reboot",   NULL,         VERB_ANY, 1,        VERB_ONLINE_ONLY,
           "Shut down and reboot userspace");
VERB_SCOPE(, verb_start_special,     "exit",             "[EXIT_CODE]", VERB_ANY, 2,       VERB_ONLINE_ONLY,
           "Request user instance or container exit");
VERB_SCOPE(, verb_switch_root,       "switch-root",      "[ROOT [INIT]]", VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY,
           "Change to a different root file system");
VERB_SCOPE(, verb_start_system_special, "sleep",         NULL,         VERB_ANY, 1,        VERB_ONLINE_ONLY,
           "Put the system to sleep (through one of the operations below)");
VERB_SCOPE(, verb_start_system_special, "suspend",       NULL,         VERB_ANY, 1,        VERB_ONLINE_ONLY,
           "Suspend the system");
VERB_SCOPE(, verb_start_system_special, "hibernate",     NULL,         VERB_ANY, 1,        VERB_ONLINE_ONLY,
           "Hibernate the system");
VERB_SCOPE(, verb_start_system_special, "hybrid-sleep",  NULL,         VERB_ANY, 1,        VERB_ONLINE_ONLY,
           "Hibernate and suspend the system");
VERB_SCOPE(, verb_start_system_special, "suspend-then-hibernate", NULL, VERB_ANY, 1,       VERB_ONLINE_ONLY,
           "Suspend the system, wake after a period of time, and hibernate");

/* Compatibility aliases / deprecated verbs hidden from --help. */
VERB_SCOPE(, verb_trivial_method,    "clear-jobs",       NULL, VERB_ANY, 1,      VERB_ONLINE_ONLY, /* help= */ NULL); /* systemctl < 4 */
VERB_SCOPE(, verb_start,             "condstop",         NULL, 2,      VERB_ANY, VERB_ONLINE_ONLY, /* help= */ NULL); /* ALTLinux */
VERB_SCOPE(, verb_start,             "reload-or-try-restart", NULL, 2, VERB_ANY, VERB_ONLINE_ONLY, /* help= */ NULL); /* systemctl <= 228 */
VERB_SCOPE(, verb_start,             "force-reload",     NULL, 2,      VERB_ANY, VERB_ONLINE_ONLY, /* help= */ NULL); /* SysV */
VERB_SCOPE(, verb_start,             "condreload",       NULL, 2,      VERB_ANY, VERB_ONLINE_ONLY, /* help= */ NULL); /* ALTLinux */
VERB_SCOPE(, verb_start,             "condrestart",      NULL, 2,      VERB_ANY, VERB_ONLINE_ONLY, /* help= */ NULL); /* RH */
VERB_SCOPE(, verb_is_active,         "check",            NULL, 2,      VERB_ANY, VERB_ONLINE_ONLY, /* help= */ NULL); /* deprecated alias of is-active */

int systemctl_main(char **args) {
        assert((uintptr_t) __start_SYSTEMD_VERBS % sizeof(void*) == 0);
        const Verb *verb = verbs_find_verb(args[0], __start_SYSTEMD_VERBS, __stop_SYSTEMD_VERBS);

        if (verb && (verb->flags & VERB_ONLINE_ONLY) && arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Verb '%s' cannot be used with --root= or --image=.",
                                       args[0] ?: verb->verb);

        return dispatch_verb(args, NULL);
}
