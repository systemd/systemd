/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Simon Peeters
***/

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

#include "sd-bus.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "analyze.h"
#include "analyze-architectures.h"
#include "analyze-blame.h"
#include "analyze-calendar.h"
#include "analyze-capability.h"
#include "analyze-cat-config.h"
#include "analyze-chid.h"
#include "analyze-compare-versions.h"
#include "analyze-condition.h"
#include "analyze-critical-chain.h"
#include "analyze-dlopen-metadata.h"
#include "analyze-dot.h"
#include "analyze-dump.h"
#include "analyze-exit-status.h"
#include "analyze-fdstore.h"
#include "analyze-filesystems.h"
#include "analyze-has-tpm2.h"
#include "analyze-image-policy.h"
#include "analyze-inspect-elf.h"
#include "analyze-log-control.h"
#include "analyze-malloc.h"
#include "analyze-nvpcrs.h"
#include "analyze-pcrs.h"
#include "analyze-plot.h"
#include "analyze-security.h"
#include "analyze-service-watchdogs.h"
#include "analyze-smbios11.h"
#include "analyze-srk.h"
#include "analyze-syscall-filter.h"
#include "analyze-time.h"
#include "analyze-timespan.h"
#include "analyze-timestamp.h"
#include "analyze-unit-files.h"
#include "analyze-unit-gdb.h"
#include "analyze-unit-paths.h"
#include "analyze-unit-shell.h"
#include "analyze-verify.h"
#include "analyze-verify-util.h"
#include "build.h"
#include "bus-error.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "calendarspec.h"
#include "dissect-image.h"
#include "extract-word.h"
#include "format-table.h"
#include "help-util.h"
#include "image-policy.h"
#include "log.h"
#include "loop-util.h"
#include "main-func.h"
#include "mount-util.h"
#include "options.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "runtime-scope.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "unit-def.h"
#include "unit-name.h"
#include "verbs.h"

DotMode arg_dot = DEP_ALL;
CapabilityMode arg_capability = CAPABILITY_LITERAL;
char **arg_dot_from_patterns = NULL, **arg_dot_to_patterns = NULL;
usec_t arg_fuzz = 0;
PagerFlags arg_pager_flags = 0;
CatFlags arg_cat_flags = 0;
BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
char *arg_debugger = NULL;
char **arg_debugger_args = NULL;
const char *arg_host = NULL;
RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
RecursiveErrors arg_recursive_errors = _RECURSIVE_ERRORS_INVALID;
bool arg_man = true;
bool arg_generators = false;
const char *arg_instance = "test_instance";
double arg_svg_timescale = 1.0;
bool arg_detailed_svg = false;
char *arg_root = NULL;
static char *arg_image = NULL;
char *arg_security_policy = NULL;
bool arg_offline = false;
unsigned arg_threshold = 100;
unsigned arg_iterations = 1;
usec_t arg_base_time = USEC_INFINITY;
char *arg_unit = NULL;
sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
bool arg_quiet = false;
char *arg_profile = NULL;
bool arg_legend = true;
bool arg_table = false;
ImagePolicy *arg_image_policy = NULL;
char *arg_drm_device_path = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_dot_from_patterns, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_dot_to_patterns, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_debugger, freep);
STATIC_DESTRUCTOR_REGISTER(arg_debugger_args, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_security_policy, freep);
STATIC_DESTRUCTOR_REGISTER(arg_drm_device_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_unit, freep);
STATIC_DESTRUCTOR_REGISTER(arg_profile, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);

int acquire_bus(sd_bus **bus, bool *use_full_bus) {
        int r;

        POINTER_MAY_BE_NULL(use_full_bus);

        if (use_full_bus && *use_full_bus) {
                r = bus_connect_transport(arg_transport, arg_host, arg_runtime_scope, bus);
                if (IN_SET(r, 0, -EHOSTDOWN))
                        return r;

                *use_full_bus = false;
        }

        return bus_connect_transport_systemd(arg_transport, arg_host, arg_runtime_scope, bus);
}

int bus_get_unit_property_strv(sd_bus *bus, const char *path, const char *property, char ***strv) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(path);
        assert(property);
        assert(strv);

        r = sd_bus_get_property_strv(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        property,
                        &error,
                        strv);
        if (r < 0)
                return log_error_errno(r, "Failed to get unit property %s: %s", property, bus_error_message(&error, r));

        return 0;
}

void time_parsing_hint(const char *p, bool calendar, bool timestamp, bool timespan) {
        if (calendar && calendar_spec_from_string(p, NULL) >= 0)
                log_notice("Hint: this expression is a valid calendar specification. "
                           "Use 'systemd-analyze calendar \"%s\"' instead?", p);
        if (timestamp && parse_timestamp(p, NULL) >= 0)
                log_notice("Hint: this expression is a valid timestamp. "
                           "Use 'systemd-analyze timestamp \"%s\"' instead?", p);
        if (timespan && parse_time(p, NULL, USEC_PER_SEC) >= 0)
                log_notice("Hint: this expression is a valid timespan. "
                           "Use 'systemd-analyze timespan \"%s\"' instead?", p);
}

static int verb_transient_settings(int argc, char *argv[], uintptr_t _data, void *userdata) {
        assert(argc >= 2);

        pager_open(arg_pager_flags);

        bool first = true;
        STRV_FOREACH(arg, strv_skip(argv, 1)) {
                UnitType t;

                t = unit_type_from_string(*arg);
                if (t < 0)
                        return log_error_errno(t, "Invalid unit type '%s'.", *arg);

                if (!first)
                        puts("");

                bus_dump_transient_settings(t);
                first = false;
        }

        return 0;
}

static int help(void) {
        static const char *const vgroups[] = {
                "Boot Analysis",
                "Dependency Analysis",
                "Configuration Files and Search Paths",
                "Enumerate OS Concepts",
                "Expression Evaluation",
                "Clock & Time",
                "Unit & Service Analysis",
                "Executable Analysis",
                "TPM Operations",
        };

        Table *vtables[ELEMENTSOF(vgroups)] = {};
        CLEANUP_ELEMENTS(vtables, table_unref_array_clear);
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        pager_open(arg_pager_flags);

        for (size_t i = 0; i < ELEMENTSOF(vgroups); i++) {
                r = verbs_get_help_table_group(vgroups[i], &vtables[i]);
                if (r < 0)
                        return r;
        }

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        assert_cc(ELEMENTSOF(vtables) == 9);
        (void) table_sync_column_widths(0, options, vtables[0], vtables[1], vtables[2],
                                        vtables[3], vtables[4], vtables[5], vtables[6],
                                        vtables[7], vtables[8]);

        help_cmdline("[OPTIONS...] COMMAND ...");
        help_abstract("Profile systemd, show unit dependencies, check unit files.");

        for (size_t i = 0; i < ELEMENTSOF(vgroups); i++) {
                help_section(vgroups[i]);
                r = table_print_or_warn(vtables[i]);
                if (r < 0)
                        return r;
        }

        help_section("Options");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("systemd-analyze", "1");

        return 0;
}

VERB_COMMON_HELP_HIDDEN(help);

/* When updating this list, including descriptions, apply changes to
 * shell-completion/bash/systemd-analyze and shell-completion/zsh/_systemd-analyze too. */

VERB_GROUP("Boot Analysis");
VERB_SCOPE(, verb_time, "time", NULL, VERB_ANY, 1, VERB_DEFAULT,
           "Print time required to boot the machine");
VERB_SCOPE(, verb_blame, "blame", NULL, VERB_ANY, 1, 0,
           "Print list of running units ordered by time to init");
VERB_SCOPE(, verb_critical_chain, "critical-chain", "[UNIT...]", VERB_ANY, VERB_ANY, 0,
           "Print a tree of the time critical chain of units");

VERB_GROUP("Dependency Analysis");
VERB_SCOPE(, verb_plot, "plot", NULL, VERB_ANY, 1, 0,
           "Output SVG graphic showing service initialization");
VERB_SCOPE(, verb_dot, "dot", "[UNIT...]", VERB_ANY, VERB_ANY, 0,
           "Output dependency graph in dot(1) format");
VERB_SCOPE(, verb_dump, "dump", "[PATTERN...]", VERB_ANY, VERB_ANY, 0,
           "Output state serialization of service manager");

VERB_GROUP("Configuration Files and Search Paths");
VERB_SCOPE(, verb_cat_config, "cat-config", "NAME|PATH...", 2, VERB_ANY, 0,
           "Show configuration file and drop-ins");
VERB_SCOPE(, verb_unit_files, "unit-files", NULL, VERB_ANY, VERB_ANY, 0,
           "List files and symlinks for units");
VERB_SCOPE(, verb_unit_paths, "unit-paths", NULL, 1, 1, 0,
           "List load directories for units");

VERB_GROUP("Enumerate OS Concepts");
VERB_SCOPE(, verb_exit_status, "exit-status", "[STATUS...]", VERB_ANY, VERB_ANY, 0,
           "List exit status definitions");
VERB_SCOPE(, verb_capabilities, "capability", "[CAP...]", VERB_ANY, VERB_ANY, 0,
           "List capability definitions");
VERB_SCOPE(, verb_syscall_filters, "syscall-filter", "[NAME...]", VERB_ANY, VERB_ANY, 0,
           "List syscalls in seccomp filters");
VERB_SCOPE(, verb_filesystems, "filesystems", "[NAME...]", VERB_ANY, VERB_ANY, 0,
           "List known filesystems");
VERB_SCOPE(, verb_architectures, "architectures", "[NAME...]", VERB_ANY, VERB_ANY, 0,
           "List known architectures");
VERB_SCOPE(, verb_smbios11, "smbios11", NULL, VERB_ANY, 1, 0,
           "List strings passed via SMBIOS Type #11");
VERB_SCOPE(, verb_chid, "chid", NULL, VERB_ANY, VERB_ANY, 0,
           "List local CHIDs");
VERB(verb_transient_settings, "transient-settings", "TYPE...", 2, VERB_ANY, 0,
     "List transient settings for unit TYPE");

VERB_GROUP("Expression Evaluation");
VERB_SCOPE(, verb_condition, "condition", "CONDITION...", VERB_ANY, VERB_ANY, 0,
           "Evaluate conditions and asserts");
VERB_SCOPE(, verb_compare_versions, "compare-versions", "V1 [OP] V2", 3, 4, 0,
           "Compare two version strings");
VERB_SCOPE(, verb_image_policy, "image-policy", "POLICY...", 2, 2, 0,
           "Analyze image policy string");

VERB_GROUP("Clock & Time");
VERB_SCOPE(, verb_calendar, "calendar", "SPEC...", 2, VERB_ANY, 0,
           "Validate repetitive calendar time events");
VERB_SCOPE(, verb_timestamp, "timestamp", "TIMESTAMP...", 2, VERB_ANY, 0,
           "Validate a timestamp");
VERB_SCOPE(, verb_timespan, "timespan", "SPAN...", 2, VERB_ANY, 0,
           "Validate a time span");

VERB_GROUP("Unit & Service Analysis");
VERB_SCOPE(, verb_verify, "verify", "FILE...", 2, VERB_ANY, 0,
           "Check unit files for correctness");
VERB_SCOPE(, verb_security, "security", "[UNIT...]", VERB_ANY, VERB_ANY, 0,
           "Analyze security of unit");
VERB_SCOPE(, verb_fdstore, "fdstore", "SERVICE...", 2, VERB_ANY, 0,
           "Show file descriptor store contents of service");
VERB_SCOPE(, verb_malloc, "malloc", "[D-BUS SERVICE...]", VERB_ANY, VERB_ANY, 0,
           "Dump malloc stats of a D-Bus service");
VERB_SCOPE(, verb_unit_gdb, "unit-gdb", "SERVICE", 2, VERB_ANY, 0,
           "Attach a debugger to the given running service");
VERB_SCOPE(, verb_unit_shell, "unit-shell", "SERVICE [COMMAND ...]", 2, VERB_ANY, 0,
           "Run command on the namespace of the service");

VERB_GROUP("Executable Analysis");
VERB_SCOPE(, verb_elf_inspection, "inspect-elf", "FILE...", 2, VERB_ANY, 0,
           "Parse and print ELF package metadata");
VERB_SCOPE(, verb_dlopen_metadata, "dlopen-metadata", "FILE", 2, 2, 0,
           "Parse and print ELF dlopen metadata");

VERB_GROUP("TPM Operations");
VERB_SCOPE(, verb_has_tpm2, "has-tpm2", NULL, VERB_ANY, 1, 0,
           "Report whether TPM2 support is available");
VERB_SCOPE(, verb_identify_tpm2, "identify-tpm2", NULL, VERB_ANY, 1, 0,
           "Show TPM2 vendor information");
VERB_SCOPE(, verb_pcrs, "pcrs", "[PCR...]", VERB_ANY, VERB_ANY, 0,
           "Show TPM2 PCRs and their names");
VERB_SCOPE(, verb_nvpcrs, "nvpcrs", "[NVPCR...]", VERB_ANY, VERB_ANY, 0,
           "Show additional TPM2 PCRs stored in NV indexes");
VERB_SCOPE(, verb_srk, "srk", "[>FILE]", VERB_ANY, 1, 0,
           "Write TPM2 SRK (to FILE)");

/* The following are deprecated and not shown in --help. */
VERB_SCOPE(, verb_log_control,        "log-level",         NULL, VERB_ANY, 2, 0, /* help= */ NULL);
VERB_SCOPE(, verb_log_control,        "log-target",        NULL, VERB_ANY, 2, 0, /* help= */ NULL);
VERB_SCOPE(, verb_log_control,        "set-log-level",     NULL, 2,        2, 0, /* help= */ NULL);
VERB_SCOPE(, verb_log_control,        "get-log-level",     NULL, VERB_ANY, 1, 0, /* help= */ NULL);
VERB_SCOPE(, verb_log_control,        "set-log-target",    NULL, 2,        2, 0, /* help= */ NULL);
VERB_SCOPE(, verb_log_control,        "get-log-target",    NULL, VERB_ANY, 1, 0, /* help= */ NULL);
VERB_SCOPE(, verb_service_watchdogs,  "service-watchdogs", NULL, VERB_ANY, 2, 0, /* help= */ NULL);

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        int r;

        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        /* For "unit-shell" the switches specified after the service name are part of the commandline
         * to execute and are not processed by us. For other verbs, we consume all options as usual.
         * To make this work, start with mode==OPTION_PARSER_RETURN_POSITIONAL_ARGS and switch to
         * either OPTION_PARSER_STOP_AT_FIRST_NONOPTION or OPTION_PARSER_NORMAL after we've seen
         * the verb. */
        OptionParser opts = { argc, argv, OPTION_PARSER_RETURN_POSITIONAL_ARGS };
        const char *verb = NULL;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_POSITIONAL:
                        verb = opts.arg;

                        assert(opts.mode == OPTION_PARSER_RETURN_POSITIONAL_ARGS);
                        if (streq(verb, "unit-shell"))
                                opts.mode = OPTION_PARSER_STOP_AT_FIRST_NONOPTION;
                        else
                                opts.mode = OPTION_PARSER_NORMAL;
                        break;

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('q', "quiet", NULL, "Do not emit hints"):
                        arg_quiet = true;
                        break;

                OPTION_LONG("recursive-errors", "MODE", "Control which units are verified"):
                        if (streq(opts.arg, "help"))
                                return DUMP_STRING_TABLE(recursive_errors, RecursiveErrors, _RECURSIVE_ERRORS_MAX);

                        r = recursive_errors_from_string(opts.arg);
                        if (r < 0)
                                return log_error_errno(r, "Unknown mode passed to --recursive-errors='%s'.", opts.arg);

                        arg_recursive_errors = r;
                        break;

                OPTION_LONG("root", "PATH", "Operate on an alternate filesystem root"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image", "PATH", "Operate on disk image as filesystem root"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image-policy", "POLICY", "Specify disk image dissection policy"):
                        r = parse_image_policy_argument(opts.arg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("system", NULL, "Operate on system systemd instance"):
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                OPTION_LONG("user", NULL, "Operate on user systemd instance"):
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                OPTION_LONG("global", NULL, "Operate on global user configuration"):
                        arg_runtime_scope = RUNTIME_SCOPE_GLOBAL;
                        break;

                OPTION_LONG("order", NULL, "Show only order in the graph"):
                        arg_dot = DEP_ORDER;
                        break;

                OPTION_LONG("require", NULL, "Show only requirement in the graph"):
                        arg_dot = DEP_REQUIRE;
                        break;

                OPTION_LONG("from-pattern", "GLOB", "Show only origins in the graph"):
                        if (strv_extend(&arg_dot_from_patterns, opts.arg) < 0)
                                return log_oom();
                        break;

                OPTION_LONG("to-pattern", "GLOB", "Show only destinations in the graph"):
                        if (strv_extend(&arg_dot_to_patterns, opts.arg) < 0)
                                return log_oom();
                        break;

                OPTION_LONG("fuzz", "SECONDS",
                            "Also print services which finished SECONDS earlier than the latest in the branch"):
                        r = parse_sec(opts.arg, &arg_fuzz);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
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

                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "man", "BOOL", "Whether to check for existence of man pages"):
                        r = parse_boolean_argument("--man", opts.arg, &arg_man);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "generators", "BOOL",
                                  "Whether to run unit generators (which requires privileges)"):
                        r = parse_boolean_argument("--generators", opts.arg, &arg_generators);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("instance", "NAME", "Specify fallback instance name for template units"):
                        arg_instance = opts.arg;
                        break;

                OPTION_LONG("offline", "BOOL", "Perform a security review on unit files"):
                        r = parse_boolean_argument("--offline", opts.arg, &arg_offline);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("threshold", "N",
                            "Exit with a non-zero status when overall exposure level is over threshold value"):
                        r = safe_atou(opts.arg, &arg_threshold);
                        if (r < 0 || arg_threshold > 100)
                                return log_error_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse threshold: %s", opts.arg);
                        break;

                OPTION_LONG("security-policy", "PATH",
                            "Use custom JSON security policy instead of built-in one"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_security_policy);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_LONG("iterations", "N", "Show the specified number of iterations"):
                        r = safe_atou(opts.arg, &arg_iterations);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse iterations: %s", opts.arg);
                        break;

                OPTION_LONG("base-time", "TIMESTAMP",
                            "Calculate calendar times relative to specified time"):
                        r = parse_timestamp(opts.arg, &arg_base_time);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --base-time= parameter: %s", opts.arg);
                        break;

                OPTION_LONG("profile", "name|PATH",
                            "Include the specified profile in the security review of the units"):
                        if (isempty(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Profile file name is empty");

                        if (is_path(opts.arg)) {
                                r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_profile);
                                if (r < 0)
                                        return r;
                                if (!endswith(arg_profile, ".conf"))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Profile file name must end with .conf: %s", arg_profile);
                        } else {
                                r = free_and_strdup(&arg_profile, opts.arg);
                                if (r < 0)
                                        return log_oom();
                        }
                        break;

                OPTION('U', "unit", "UNIT", "Evaluate conditions and asserts of unit"): {
                        _cleanup_free_ char *mangled = NULL;

                        r = unit_name_mangle(opts.arg, UNIT_NAME_MANGLE_WARN, &mangled);
                        if (r < 0)
                                return log_error_errno(r, "Failed to mangle unit name %s: %m", opts.arg);

                        free_and_replace(arg_unit, mangled);
                        break;
                }

                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "table", NULL,
                                  "Output plot's raw time data as a table"):
                        arg_table = true;
                        break;

                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "no-legend", NULL,
                                  "Disable column headers and hints in plot with either --table or --json="):
                        arg_legend = false;
                        break;

                OPTION_LONG("tldr", NULL, "Skip comments and empty lines"):
                        arg_cat_flags = CAT_TLDR;
                        break;

                OPTION('m', "mask", NULL, "Parse parameter as numeric capability mask"):
                        arg_capability = CAPABILITY_MASK;
                        break;

                OPTION_LONG("scale-svg", "FACTOR", "Stretch x-axis of plot by FACTOR (default: 1.0)"):
                        arg_svg_timescale = strtod(opts.arg, NULL);
                        break;

                OPTION_LONG("detailed", NULL,
                            "Add more details to SVG plot, e.g. show activation timestamps"):
                        arg_detailed_svg = true;
                        break;

                OPTION_LONG("drm-device", "PATH", "Use this DRM device sysfs path to get EDID"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_drm_device_path);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("debugger", "DEBUGGER", "Use the given debugger"):
                        r = free_and_strdup_warn(&arg_debugger, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION('A', "debugger-arguments", "ARGS", "Pass the given arguments to the debugger"): {
                        _cleanup_strv_free_ char **l = NULL;
                        r = strv_split_full(&l, opts.arg, WHITESPACE, EXTRACT_UNQUOTE);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse debugger arguments '%s': %m", opts.arg);
                        strv_free_and_replace(arg_debugger_args, l);
                        break;
                }
                }

        _cleanup_strv_free_ char **args = strv_copy(option_parser_get_args(&opts)); /* args is [arg1, arg2, …] */
        if (!args || strv_prepend(&args, verb) < 0)                                 /* args is now [arg0, arg1, arg2, …] */
                return log_oom();

        if (arg_offline && !streq_ptr(verb, "security"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --offline= is only supported for security right now.");

        if (arg_offline && strv_length(args) < 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --offline= requires one or more units to perform a security review.");

        if (arg_json_format_flags != SD_JSON_FORMAT_OFF &&
            !STRPTR_IN_SET(verb, "security", "inspect-elf", "dlopen-metadata", "plot", "fdstore", "pcrs", "nvpcrs", "architectures", "capability", "exit-status"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --json= is only supported for security, inspect-elf, dlopen-metadata, plot, fdstore, pcrs, nvpcrs, architectures, capability, exit-status right now.");

        if (arg_threshold != 100 && !streq_ptr(verb, "security"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --threshold= is only supported for security right now.");

        if (arg_runtime_scope == RUNTIME_SCOPE_GLOBAL && !streq_ptr(verb, "unit-paths"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --global only makes sense with verb unit-paths.");

        if (streq_ptr(verb, "cat-config") && arg_runtime_scope == RUNTIME_SCOPE_USER)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --user is not supported for cat-config right now.");

        if (arg_security_policy && !streq_ptr(verb, "security"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --security-policy= is only supported for security.");

        if ((arg_root || arg_image) &&
            !STRPTR_IN_SET(verb, "cat-config", "verify", "condition", "inspect-elf", "unit-gdb") &&
            (!(streq_ptr(verb, "security") && arg_offline)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Options --root= and --image= are only supported for cat-config, verify, condition, unit-gdb, and security when used with --offline= right now.");

        /* Having both an image and a root is not supported by the code */
        if (arg_root && arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        if (arg_unit && !streq_ptr(verb, "condition"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --unit= is only supported for condition");

        if (streq_ptr(verb, "condition") && !arg_unit && strv_length(args) < 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too few arguments for condition");

        if (streq_ptr(verb, "condition") && arg_unit && strv_length(args) > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No conditions can be passed if --unit= is used.");

        if (arg_table && !streq_ptr(verb, "plot"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --table is only supported for plot right now.");

        if (arg_table && sd_json_format_enabled(arg_json_format_flags))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--table and --json= are mutually exclusive.");

        if (arg_capability != CAPABILITY_LITERAL && !streq_ptr(verb, "capability"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --mask is only supported for capability.");

        if (arg_drm_device_path && !streq_ptr(verb, "chid"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --drm-device is only supported for chid right now.");

        *ret_args = TAKE_PTR(args);
        return 1; /* work to do */
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        _cleanup_strv_free_ char **args = NULL;
        int r;

        setlocale(LC_ALL, "");
        setlocale(LC_NUMERIC, "C"); /* we want to format/parse floats in C style */

        log_setup();

        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        /* Open up and mount the image */
        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                arg_image_policy,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_READ_ONLY |
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

        return dispatch_verb_with_args(args, NULL);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
