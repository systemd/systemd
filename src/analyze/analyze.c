/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Simon Peeters
***/

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "analyze.h"
#include "analyze-architectures.h"
#include "analyze-blame.h"
#include "analyze-calendar.h"
#include "analyze-capability.h"
#include "analyze-cat-config.h"
#include "analyze-compare-versions.h"
#include "analyze-condition.h"
#include "analyze-critical-chain.h"
#include "analyze-dot.h"
#include "analyze-dump.h"
#include "analyze-exit-status.h"
#include "analyze-fdstore.h"
#include "analyze-filesystems.h"
#include "analyze-image-policy.h"
#include "analyze-inspect-elf.h"
#include "analyze-log-control.h"
#include "analyze-malloc.h"
#include "analyze-pcrs.h"
#include "analyze-plot.h"
#include "analyze-security.h"
#include "analyze-service-watchdogs.h"
#include "analyze-srk.h"
#include "analyze-syscall-filter.h"
#include "analyze-time.h"
#include "analyze-time-data.h"
#include "analyze-timespan.h"
#include "analyze-timestamp.h"
#include "analyze-unit-files.h"
#include "analyze-unit-paths.h"
#include "analyze-verify.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-unit-util.h"
#include "calendarspec.h"
#include "cap-list.h"
#include "capability-util.h"
#include "conf-files.h"
#include "copy.h"
#include "constants.h"
#include "exit-status.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "filesystems.h"
#include "format-table.h"
#include "glob-util.h"
#include "hashmap.h"
#include "locale-util.h"
#include "log.h"
#include "main-func.h"
#include "mount-util.h"
#include "nulstr-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "rm-rf.h"
#if HAVE_SECCOMP
#  include "seccomp-util.h"
#endif
#include "sort-util.h"
#include "special.h"
#include "stat-util.h"
#include "string-table.h"
#include "strv.h"
#include "strxcpyx.h"
#include "terminal-util.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "unit-name.h"
#include "verb-log-control.h"
#include "verbs.h"

DotMode arg_dot = DEP_ALL;
char **arg_dot_from_patterns = NULL, **arg_dot_to_patterns = NULL;
usec_t arg_fuzz = 0;
PagerFlags arg_pager_flags = 0;
CatFlags arg_cat_flags = 0;
BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
const char *arg_host = NULL;
RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
RecursiveErrors arg_recursive_errors = _RECURSIVE_ERRORS_INVALID;
bool arg_man = true;
bool arg_generators = false;
char *arg_root = NULL;
static char *arg_image = NULL;
char *arg_security_policy = NULL;
bool arg_offline = false;
unsigned arg_threshold = 100;
unsigned arg_iterations = 1;
usec_t arg_base_time = USEC_INFINITY;
char *arg_unit = NULL;
JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
bool arg_quiet = false;
char *arg_profile = NULL;
bool arg_legend = true;
bool arg_table = false;
ImagePolicy *arg_image_policy = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_dot_from_patterns, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_dot_to_patterns, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_security_policy, freep);
STATIC_DESTRUCTOR_REGISTER(arg_unit, freep);
STATIC_DESTRUCTOR_REGISTER(arg_profile, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);

int acquire_bus(sd_bus **bus, bool *use_full_bus) {
        int r;

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

int dump_fd_reply(sd_bus_message *message) {
        int fd, r;

        assert(message);

        r = sd_bus_message_read(message, "h", &fd);
        if (r < 0)
                return bus_log_parse_error(r);

        fflush(stdout);
        r = copy_bytes(fd, STDOUT_FILENO, UINT64_MAX, 0);
        if (r < 0)
                return r;

        return 1;  /* Success */
}

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL, *dot_link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("systemd-analyze", "1", &link);
        if (r < 0)
                return log_oom();

        /* Not using terminal_urlify_man() for this, since we don't want the "man page" text suffix in this case. */
        r = terminal_urlify("man:dot(1)", "dot(1)", &dot_link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] COMMAND ...\n\n"
               "%sProfile systemd, show unit dependencies, check unit files.%s\n"
               "\nCommands:\n"
               "  [time]                     Print time required to boot the machine\n"
               "  blame                      Print list of running units ordered by\n"
               "                             time to init\n"
               "  critical-chain [UNIT...]   Print a tree of the time critical chain\n"
               "                             of units\n"
               "  plot                       Output SVG graphic showing service\n"
               "                             initialization\n"
               "  dot [UNIT...]              Output dependency graph in %s format\n"
               "  dump [PATTERN...]          Output state serialization of service\n"
               "                             manager\n"
               "  cat-config NAME|PATH...    Show configuration file and drop-ins\n"
               "  unit-files                 List files and symlinks for units\n"
               "  unit-paths                 List load directories for units\n"
               "  exit-status [STATUS...]    List exit status definitions\n"
               "  capability [CAP...]        List capability definitions\n"
               "  syscall-filter [NAME...]   List syscalls in seccomp filters\n"
               "  filesystems [NAME...]      List known filesystems\n"
               "  architectures [NAME...]    List known architectures\n"
               "  condition CONDITION...     Evaluate conditions and asserts\n"
               "  compare-versions VERSION1 [OP] VERSION2\n"
               "                             Compare two version strings\n"
               "  verify FILE...             Check unit files for correctness\n"
               "  calendar SPEC...           Validate repetitive calendar time\n"
               "                             events\n"
               "  timestamp TIMESTAMP...     Validate a timestamp\n"
               "  timespan SPAN...           Validate a time span\n"
               "  security [UNIT...]         Analyze security of unit\n"
               "  inspect-elf FILE...        Parse and print ELF package metadata\n"
               "  malloc [D-BUS SERVICE...]  Dump malloc stats of a D-Bus service\n"
               "  fdstore SERVICE...         Show file descriptor store contents of service\n"
               "  image-policy POLICY...     Analyze image policy string\n"
               "  pcrs [PCR...]              Show TPM2 PCRs and their names\n"
               "  srk > FILE                 Write TPM2 SRK to stdout\n"
               "\nOptions:\n"
               "     --recursive-errors=MODE Control which units are verified\n"
               "     --offline=BOOL          Perform a security review on unit file(s)\n"
               "     --threshold=N           Exit with a non-zero status when overall\n"
               "                             exposure level is over threshold value\n"
               "     --security-policy=PATH  Use custom JSON security policy instead\n"
               "                             of built-in one\n"
               "     --json=pretty|short|off Generate JSON output of the security\n"
               "                             analysis table, or plot's raw time data\n"
               "     --no-pager              Do not pipe output into a pager\n"
               "     --no-legend             Disable column headers and hints in plot\n"
               "                             with either --table or --json=\n"
               "     --system                Operate on system systemd instance\n"
               "     --user                  Operate on user systemd instance\n"
               "     --global                Operate on global user configuration\n"
               "  -H --host=[USER@]HOST      Operate on remote host\n"
               "  -M --machine=CONTAINER     Operate on local container\n"
               "     --order                 Show only order in the graph\n"
               "     --require               Show only requirement in the graph\n"
               "     --from-pattern=GLOB     Show only origins in the graph\n"
               "     --to-pattern=GLOB       Show only destinations in the graph\n"
               "     --fuzz=SECONDS          Also print services which finished SECONDS\n"
               "                             earlier than the latest in the branch\n"
               "     --man[=BOOL]            Do [not] check for existence of man pages\n"
               "     --generators[=BOOL]     Do [not] run unit generators\n"
               "                             (requires privileges)\n"
               "     --iterations=N          Show the specified number of iterations\n"
               "     --base-time=TIMESTAMP   Calculate calendar times relative to\n"
               "                             specified time\n"
               "     --profile=name|PATH     Include the specified profile in the\n"
               "                             security review of the unit(s)\n"
               "     --table                 Output plot's raw time data as a table\n"
               "  -h --help                  Show this help\n"
               "     --version               Show package version\n"
               "  -q --quiet                 Do not emit hints\n"
               "     --tldr                  Skip comments and empty lines\n"
               "     --root=PATH             Operate on an alternate filesystem root\n"
               "     --image=PATH            Operate on disk image as filesystem root\n"
               "     --image-policy=POLICY   Specify disk image dissection policy\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal(),
               dot_link,
               link);

        /* When updating this list, including descriptions, apply changes to
         * shell-completion/bash/systemd-analyze and shell-completion/zsh/_systemd-analyze too. */

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_ORDER,
                ARG_REQUIRE,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_IMAGE_POLICY,
                ARG_SYSTEM,
                ARG_USER,
                ARG_GLOBAL,
                ARG_DOT_FROM_PATTERN,
                ARG_DOT_TO_PATTERN,
                ARG_FUZZ,
                ARG_NO_PAGER,
                ARG_MAN,
                ARG_GENERATORS,
                ARG_ITERATIONS,
                ARG_BASE_TIME,
                ARG_RECURSIVE_ERRORS,
                ARG_OFFLINE,
                ARG_THRESHOLD,
                ARG_SECURITY_POLICY,
                ARG_JSON,
                ARG_PROFILE,
                ARG_TABLE,
                ARG_NO_LEGEND,
                ARG_TLDR,
        };

        static const struct option options[] = {
                { "help",             no_argument,       NULL, 'h'                  },
                { "version",          no_argument,       NULL, ARG_VERSION          },
                { "quiet",            no_argument,       NULL, 'q'                  },
                { "order",            no_argument,       NULL, ARG_ORDER            },
                { "require",          no_argument,       NULL, ARG_REQUIRE          },
                { "root",             required_argument, NULL, ARG_ROOT             },
                { "image",            required_argument, NULL, ARG_IMAGE            },
                { "image-policy",     required_argument, NULL, ARG_IMAGE_POLICY     },
                { "recursive-errors", required_argument, NULL, ARG_RECURSIVE_ERRORS },
                { "offline",          required_argument, NULL, ARG_OFFLINE          },
                { "threshold",        required_argument, NULL, ARG_THRESHOLD        },
                { "security-policy",  required_argument, NULL, ARG_SECURITY_POLICY  },
                { "system",           no_argument,       NULL, ARG_SYSTEM           },
                { "user",             no_argument,       NULL, ARG_USER             },
                { "global",           no_argument,       NULL, ARG_GLOBAL           },
                { "from-pattern",     required_argument, NULL, ARG_DOT_FROM_PATTERN },
                { "to-pattern",       required_argument, NULL, ARG_DOT_TO_PATTERN   },
                { "fuzz",             required_argument, NULL, ARG_FUZZ             },
                { "no-pager",         no_argument,       NULL, ARG_NO_PAGER         },
                { "man",              optional_argument, NULL, ARG_MAN              },
                { "generators",       optional_argument, NULL, ARG_GENERATORS       },
                { "host",             required_argument, NULL, 'H'                  },
                { "machine",          required_argument, NULL, 'M'                  },
                { "iterations",       required_argument, NULL, ARG_ITERATIONS       },
                { "base-time",        required_argument, NULL, ARG_BASE_TIME        },
                { "unit",             required_argument, NULL, 'U'                  },
                { "json",             required_argument, NULL, ARG_JSON             },
                { "profile",          required_argument, NULL, ARG_PROFILE          },
                { "table",            optional_argument, NULL, ARG_TABLE            },
                { "no-legend",        optional_argument, NULL, ARG_NO_LEGEND        },
                { "tldr",             no_argument,       NULL, ARG_TLDR             },
                {}
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hH:M:U:q", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_RECURSIVE_ERRORS:
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(recursive_errors, RecursiveErrors, _RECURSIVE_ERRORS_MAX);
                                return 0;
                        }
                        r = recursive_errors_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Unknown mode passed to --recursive-errors='%s'.", optarg);

                        arg_recursive_errors = r;
                        break;

                case ARG_ROOT:
                        r = parse_path_argument(optarg, /* suppress_root= */ true, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE_POLICY:
                        r = parse_image_policy_argument(optarg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                case ARG_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                case ARG_GLOBAL:
                        arg_runtime_scope = RUNTIME_SCOPE_GLOBAL;
                        break;

                case ARG_ORDER:
                        arg_dot = DEP_ORDER;
                        break;

                case ARG_REQUIRE:
                        arg_dot = DEP_REQUIRE;
                        break;

                case ARG_DOT_FROM_PATTERN:
                        if (strv_extend(&arg_dot_from_patterns, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_DOT_TO_PATTERN:
                        if (strv_extend(&arg_dot_to_patterns, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_FUZZ:
                        r = parse_sec(optarg, &arg_fuzz);
                        if (r < 0)
                                return r;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
                        break;

                case ARG_MAN:
                        r = parse_boolean_argument("--man", optarg, &arg_man);
                        if (r < 0)
                                return r;
                        break;

                case ARG_GENERATORS:
                        r = parse_boolean_argument("--generators", optarg, &arg_generators);
                        if (r < 0)
                                return r;
                        break;

                case ARG_OFFLINE:
                        r = parse_boolean_argument("--offline", optarg, &arg_offline);
                        if (r < 0)
                                return r;
                        break;

                case ARG_THRESHOLD:
                        r = safe_atou(optarg, &arg_threshold);
                        if (r < 0 || arg_threshold > 100)
                                return log_error_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL), "Failed to parse threshold: %s", optarg);

                        break;

                case ARG_SECURITY_POLICY:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_security_policy);
                        if (r < 0)
                                return r;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                case ARG_ITERATIONS:
                        r = safe_atou(optarg, &arg_iterations);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse iterations: %s", optarg);
                        break;

                case ARG_BASE_TIME:
                        r = parse_timestamp(optarg, &arg_base_time);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --base-time= parameter: %s", optarg);
                        break;

                case ARG_PROFILE:
                        if (isempty(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Profile file name is empty");

                        if (is_path(optarg)) {
                                r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_profile);
                                if (r < 0)
                                        return r;
                                if (!endswith(arg_profile, ".conf"))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Profile file name must end with .conf: %s", arg_profile);
                        } else {
                                r = free_and_strdup(&arg_profile, optarg);
                                if (r < 0)
                                        return log_oom();
                        }

                        break;

                case 'U': {
                        _cleanup_free_ char *mangled = NULL;

                        r = unit_name_mangle(optarg, UNIT_NAME_MANGLE_WARN, &mangled);
                        if (r < 0)
                                return log_error_errno(r, "Failed to mangle unit name %s: %m", optarg);

                        free_and_replace(arg_unit, mangled);
                        break;
                }

                case ARG_TABLE:
                        arg_table = true;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_TLDR:
                        arg_cat_flags = CAT_TLDR;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_offline && !streq_ptr(argv[optind], "security"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --offline= is only supported for security right now.");

        if (arg_json_format_flags != JSON_FORMAT_OFF && !STRPTR_IN_SET(argv[optind], "security", "inspect-elf", "plot", "fdstore", "pcrs", "architectures", "capability", "exit-status"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --json= is only supported for security, inspect-elf, plot, fdstore, pcrs, architectures, capability, exit-status right now.");

        if (arg_threshold != 100 && !streq_ptr(argv[optind], "security"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --threshold= is only supported for security right now.");

        if (arg_runtime_scope == RUNTIME_SCOPE_GLOBAL &&
            !STR_IN_SET(argv[optind] ?: "time", "dot", "unit-paths", "verify"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --global only makes sense with verbs dot, unit-paths, verify.");

        if (streq_ptr(argv[optind], "cat-config") && arg_runtime_scope == RUNTIME_SCOPE_USER)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --user is not supported for cat-config right now.");

        if (arg_security_policy && !streq_ptr(argv[optind], "security"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --security-policy= is only supported for security.");

        if ((arg_root || arg_image) && (!STRPTR_IN_SET(argv[optind], "cat-config", "verify", "condition")) &&
           (!(streq_ptr(argv[optind], "security") && arg_offline)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Options --root= and --image= are only supported for cat-config, verify, condition and security when used with --offline= right now.");

        /* Having both an image and a root is not supported by the code */
        if (arg_root && arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        if (arg_unit && !streq_ptr(argv[optind], "condition"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --unit= is only supported for condition");

        if (streq_ptr(argv[optind], "condition") && !arg_unit && optind >= argc - 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too few arguments for condition");

        if (streq_ptr(argv[optind], "condition") && arg_unit && optind < argc - 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No conditions can be passed if --unit= is used.");

        if ((!arg_legend && !STRPTR_IN_SET(argv[optind], "plot", "architectures")) ||
           (streq_ptr(argv[optind], "plot") && !arg_legend && !arg_table && FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --no-legend is only supported for plot with either --table or --json=.");

        if (arg_table && !streq_ptr(argv[optind], "plot"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --table is only supported for plot right now.");

        if (arg_table && !FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--table and --json= are mutually exclusive.");

        return 1; /* work to do */
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;

        static const Verb verbs[] = {
                { "help",              VERB_ANY, VERB_ANY, 0,            help                   },
                { "time",              VERB_ANY, 1,        VERB_DEFAULT, verb_time              },
                { "blame",             VERB_ANY, 1,        0,            verb_blame             },
                { "critical-chain",    VERB_ANY, VERB_ANY, 0,            verb_critical_chain    },
                { "plot",              VERB_ANY, 1,        0,            verb_plot              },
                { "dot",               VERB_ANY, VERB_ANY, 0,            verb_dot               },
                /* ↓ The following seven verbs are deprecated, from here … ↓ */
                { "log-level",         VERB_ANY, 2,        0,            verb_log_control       },
                { "log-target",        VERB_ANY, 2,        0,            verb_log_control       },
                { "set-log-level",     2,        2,        0,            verb_log_control       },
                { "get-log-level",     VERB_ANY, 1,        0,            verb_log_control       },
                { "set-log-target",    2,        2,        0,            verb_log_control       },
                { "get-log-target",    VERB_ANY, 1,        0,            verb_log_control       },
                { "service-watchdogs", VERB_ANY, 2,        0,            verb_service_watchdogs },
                /* ↑ … until here ↑ */
                { "dump",              VERB_ANY, VERB_ANY, 0,            verb_dump              },
                { "cat-config",        2,        VERB_ANY, 0,            verb_cat_config        },
                { "unit-files",        VERB_ANY, VERB_ANY, 0,            verb_unit_files        },
                { "unit-paths",        1,        1,        0,            verb_unit_paths        },
                { "exit-status",       VERB_ANY, VERB_ANY, 0,            verb_exit_status       },
                { "syscall-filter",    VERB_ANY, VERB_ANY, 0,            verb_syscall_filters   },
                { "capability",        VERB_ANY, VERB_ANY, 0,            verb_capabilities      },
                { "filesystems",       VERB_ANY, VERB_ANY, 0,            verb_filesystems       },
                { "condition",         VERB_ANY, VERB_ANY, 0,            verb_condition         },
                { "compare-versions",  3,        4,        0,            verb_compare_versions  },
                { "verify",            2,        VERB_ANY, 0,            verb_verify            },
                { "calendar",          2,        VERB_ANY, 0,            verb_calendar          },
                { "timestamp",         2,        VERB_ANY, 0,            verb_timestamp         },
                { "timespan",          2,        VERB_ANY, 0,            verb_timespan          },
                { "security",          VERB_ANY, VERB_ANY, 0,            verb_security          },
                { "inspect-elf",       2,        VERB_ANY, 0,            verb_elf_inspection    },
                { "malloc",            VERB_ANY, VERB_ANY, 0,            verb_malloc            },
                { "fdstore",           2,        VERB_ANY, 0,            verb_fdstore           },
                { "image-policy",      2,        2,        0,            verb_image_policy      },
                { "pcrs",              VERB_ANY, VERB_ANY, 0,            verb_pcrs              },
                { "srk",               VERB_ANY, 1,        0,            verb_srk               },
                { "architectures",     VERB_ANY, VERB_ANY, 0,            verb_architectures     },
                {}
        };

        int r;

        setlocale(LC_ALL, "");
        setlocale(LC_NUMERIC, "C"); /* we want to format/parse floats in C style */

        log_setup();

        r = parse_argv(argc, argv);
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
                                DISSECT_IMAGE_READ_ONLY,
                                &mounted_dir,
                                /* ret_dir_fd= */ NULL,
                                &loop_device);
                if (r < 0)
                        return r;

                arg_root = strdup(mounted_dir);
                if (!arg_root)
                        return log_oom();
        }

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
