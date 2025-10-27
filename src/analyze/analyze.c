/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Simon Peeters
***/

#include <getopt.h>
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
#include "image-policy.h"
#include "log.h"
#include "loop-util.h"
#include "main-func.h"
#include "mount-util.h"
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

static int verb_transient_settings(int argc, char *argv[], void *userdata) {
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

        printf("%1$s [OPTIONS...] COMMAND ...\n\n"
               "%5$sProfile systemd, show unit dependencies, check unit files.%6$s\n"
               "\n%3$sBoot Analysis:%4$s\n"
               "  [time]                     Print time required to boot the machine\n"
               "  blame                      Print list of running units ordered by\n"
               "                             time to init\n"
               "  critical-chain [UNIT...]   Print a tree of the time critical chain\n"
               "                             of units\n"
               "\n%3$sDependency Analysis:%4$s\n"
               "  plot                       Output SVG graphic showing service\n"
               "                             initialization\n"
               "  dot [UNIT...]              Output dependency graph in %7$s format\n"
               "  dump [PATTERN...]          Output state serialization of service\n"
               "                             manager\n"
               "\n%3$sConfiguration Files and Search Paths:%4$s\n"
               "  cat-config NAME|PATH...    Show configuration file and drop-ins\n"
               "  unit-files                 List files and symlinks for units\n"
               "  unit-paths                 List load directories for units\n"
               "\n%3$sEnumerate OS Concepts:%4$s\n"
               "  exit-status [STATUS...]    List exit status definitions\n"
               "  capability [CAP...]        List capability definitions\n"
               "  syscall-filter [NAME...]   List syscalls in seccomp filters\n"
               "  filesystems [NAME...]      List known filesystems\n"
               "  architectures [NAME...]    List known architectures\n"
               "  smbios11                   List strings passed via SMBIOS Type #11\n"
               "  chid                       List local CHIDs\n"
               "  transient-settings TYPE... List transient settings for unit TYPE\n"
               "\n%3$sExpression Evaluation:%4$s\n"
               "  condition CONDITION...     Evaluate conditions and asserts\n"
               "  compare-versions VERSION1 [OP] VERSION2\n"
               "                             Compare two version strings\n"
               "  image-policy POLICY...     Analyze image policy string\n"
               "\n%3$sClock & Time:%4$s\n"
               "  calendar SPEC...           Validate repetitive calendar time\n"
               "                             events\n"
               "  timestamp TIMESTAMP...     Validate a timestamp\n"
               "  timespan SPAN...           Validate a time span\n"
               "\n%3$sUnit & Service Analysis:%4$s\n"
               "  verify FILE...             Check unit files for correctness\n"
               "  security [UNIT...]         Analyze security of unit\n"
               "  fdstore SERVICE...         Show file descriptor store contents of service\n"
               "  malloc [D-BUS SERVICE...]  Dump malloc stats of a D-Bus service\n"
               "  unit-gdb SERVICE           Attach a debugger to the given running service\n"
               "  unit-shell SERVICE [Command]\n"
               "                             Run command on the namespace of the service\n"
               "\n%3$sExecutable Analysis:%4$s\n"
               "  inspect-elf FILE...        Parse and print ELF package metadata\n"
               "\n%3$sTPM Operations:%4$s\n"
               "  has-tpm2                   Report whether TPM2 support is available\n"
               "  pcrs [PCR...]              Show TPM2 PCRs and their names\n"
               "  srk [>FILE]                Write TPM2 SRK (to FILE)\n"
               "\n%3$sOptions:%4$s\n"
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
               "     --instance=NAME         Specify fallback instance name for template units\n"
               "     --iterations=N          Show the specified number of iterations\n"
               "     --base-time=TIMESTAMP   Calculate calendar times relative to\n"
               "                             specified time\n"
               "     --profile=name|PATH     Include the specified profile in the\n"
               "                             security review of the unit(s)\n"
               "     --unit=UNIT             Evaluate conditions and asserts of unit\n"
               "     --table                 Output plot's raw time data as a table\n"
               "     --scale-svg=FACTOR      Stretch x-axis of plot by FACTOR (default: 1.0)\n"
               "     --detailed              Add more details to SVG plot,\n"
               "                             e.g. show activation timestamps\n"
               "  -h --help                  Show this help\n"
               "     --version               Show package version\n"
               "  -q --quiet                 Do not emit hints\n"
               "     --tldr                  Skip comments and empty lines\n"
               "     --root=PATH             Operate on an alternate filesystem root\n"
               "     --image=PATH            Operate on disk image as filesystem root\n"
               "     --image-policy=POLICY   Specify disk image dissection policy\n"
               "  -m --mask                  Parse parameter as numeric capability mask\n"
               "     --drm-device=PATH       Use this DRM device sysfs path to get EDID\n"
               "     --debugger=DEBUGGER     Use the given debugger\n"
               "  -A --debugger-arguments=ARGS\n"
               "                             Pass the given arguments to the debugger\n"

               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal(),
               dot_link);

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
                ARG_INSTANCE,
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
                ARG_SCALE_FACTOR_SVG,
                ARG_DETAILED_SVG,
                ARG_DRM_DEVICE_PATH,
                ARG_DEBUGGER,
        };

        static const struct option options[] = {
                { "help",               no_argument,       NULL, 'h'                  },
                { "version",            no_argument,       NULL, ARG_VERSION          },
                { "quiet",              no_argument,       NULL, 'q'                  },
                { "order",              no_argument,       NULL, ARG_ORDER            },
                { "require",            no_argument,       NULL, ARG_REQUIRE          },
                { "root",               required_argument, NULL, ARG_ROOT             },
                { "image",              required_argument, NULL, ARG_IMAGE            },
                { "image-policy",       required_argument, NULL, ARG_IMAGE_POLICY     },
                { "recursive-errors"  , required_argument, NULL, ARG_RECURSIVE_ERRORS },
                { "offline",            required_argument, NULL, ARG_OFFLINE          },
                { "threshold",          required_argument, NULL, ARG_THRESHOLD        },
                { "security-policy",    required_argument, NULL, ARG_SECURITY_POLICY  },
                { "system",             no_argument,       NULL, ARG_SYSTEM           },
                { "user",               no_argument,       NULL, ARG_USER             },
                { "global",             no_argument,       NULL, ARG_GLOBAL           },
                { "from-pattern",       required_argument, NULL, ARG_DOT_FROM_PATTERN },
                { "to-pattern",         required_argument, NULL, ARG_DOT_TO_PATTERN   },
                { "fuzz",               required_argument, NULL, ARG_FUZZ             },
                { "no-pager",           no_argument,       NULL, ARG_NO_PAGER         },
                { "man",                optional_argument, NULL, ARG_MAN              },
                { "generators",         optional_argument, NULL, ARG_GENERATORS       },
                { "instance",           required_argument, NULL, ARG_INSTANCE         },
                { "host",               required_argument, NULL, 'H'                  },
                { "machine",            required_argument, NULL, 'M'                  },
                { "iterations",         required_argument, NULL, ARG_ITERATIONS       },
                { "base-time",          required_argument, NULL, ARG_BASE_TIME        },
                { "unit",               required_argument, NULL, 'U'                  },
                { "json",               required_argument, NULL, ARG_JSON             },
                { "profile",            required_argument, NULL, ARG_PROFILE          },
                { "table",              optional_argument, NULL, ARG_TABLE            },
                { "no-legend",          optional_argument, NULL, ARG_NO_LEGEND        },
                { "tldr",               no_argument,       NULL, ARG_TLDR             },
                { "mask",               no_argument,       NULL, 'm'                  },
                { "scale-svg",          required_argument, NULL, ARG_SCALE_FACTOR_SVG },
                { "detailed",           no_argument,       NULL, ARG_DETAILED_SVG     },
                { "drm-device",         required_argument, NULL, ARG_DRM_DEVICE_PATH  },
                { "debugger",           required_argument, NULL, ARG_DEBUGGER         },
                { "debugger-arguments", required_argument, NULL, 'A'                  },
                {}
        };

        bool reorder = false;
        int r, c, unit_shell = -1;

        assert(argc >= 0);
        assert(argv);

        /* Resetting to 0 forces the invocation of an internal initialization routine of getopt_long()
         * that checks for GNU extensions in optstring ('-' or '+; at the beginning). */
        optind = 0;

        for (;;) {
                static const char option_string[] = "-hqH:M:U:mA:";

                c = getopt_long(argc, argv, option_string + reorder, options, NULL);
                if (c < 0)
                        break;

                switch (c) {

                case 1: /* getopt_long() returns 1 if "-" was the first character of the option string, and a
                         * non-option argument was discovered. */

                        assert(!reorder);

                        /* We generally are fine with the fact that getopt_long() reorders the command line, and looks
                         * for switches after the main verb. However, for "unit-shell" we really don't want that, since we
                         * want that switches specified after the service name are passed to the program to execute,
                         * and not processed by us. To make this possible, we'll first invoke getopt_long() with
                         * reordering disabled (i.e. with the "-" prefix in the option string), looking for the first
                         * non-option parameter. If it's the verb "unit-shell" we remember its position and continue
                         * processing options. In this case, as soon as we hit the next non-option argument we found
                         * the service name, and stop further processing. If the first non-option argument is any other
                         * verb than "unit-shell" we switch to normal reordering mode and continue processing arguments
                         * normally. */

                        if (unit_shell >= 0) {
                                optind--; /* don't process this argument, go one step back */
                                goto done;
                        }
                        if (streq(optarg, "unit-shell"))
                                /* Remember the position of the "unit_shell" verb, and continue processing normally. */
                                unit_shell = optind - 1;
                        else {
                                int saved_optind;

                                /* Ok, this is some other verb. In this case, turn on reordering again, and continue
                                 * processing normally. */
                                reorder = true;

                                /* We changed the option string. getopt_long() only looks at it again if we invoke it
                                 * at least once with a reset option index. Hence, let's reset the option index here,
                                 * then invoke getopt_long() again (ignoring what it has to say, after all we most
                                 * likely already processed it), and the bump the option index so that we read the
                                 * intended argument again. */
                                saved_optind = optind;
                                optind = 0;
                                (void) getopt_long(argc, argv, option_string + reorder, options, NULL);
                                optind = saved_optind - 1; /* go one step back, process this argument again */
                        }

                        break;

                case 'h':
                        return help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_RECURSIVE_ERRORS:
                        if (streq(optarg, "help"))
                                return DUMP_STRING_TABLE(recursive_errors, RecursiveErrors, _RECURSIVE_ERRORS_MAX);

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
                        r = parse_machine_argument(optarg, &arg_host, &arg_transport);
                        if (r < 0)
                                return r;
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

                case ARG_INSTANCE:
                        arg_instance = optarg;
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

                case 'm':
                        arg_capability = CAPABILITY_MASK;
                        break;

                case ARG_SCALE_FACTOR_SVG:
                        arg_svg_timescale = strtod(optarg, NULL);
                        break;

                case ARG_DETAILED_SVG:
                        arg_detailed_svg = true;
                        break;

                case ARG_DRM_DEVICE_PATH:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_drm_device_path);
                        if (r < 0)
                                return r;
                        break;

                case ARG_DEBUGGER:
                        r = free_and_strdup_warn(&arg_debugger, optarg);
                        if (r < 0)
                                return r;
                        break;

                case 'A': {
                        _cleanup_strv_free_ char **l = NULL;
                        r = strv_split_full(&l, optarg, WHITESPACE, EXTRACT_UNQUOTE);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse debugger arguments '%s': %m", optarg);
                        strv_free_and_replace(arg_debugger_args, l);
                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

done:
        if (unit_shell >= 0) {
                char *t;

                /* We found the "unit-shell" verb while processing the argument list. Since we turned off reordering of the
                 * argument list initially let's readjust it now, and move the "unit-shell" verb to the back. */

                optind -= 1; /* place the option index where the "unit-shell" verb will be placed */

                t = argv[unit_shell];
                for (int i = unit_shell; i < optind; i++)
                        argv[i] = argv[i+1];
                argv[optind] = t;
        }

        if (arg_offline && !streq_ptr(argv[optind], "security"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --offline= is only supported for security right now.");

        if (arg_offline && optind >= argc - 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --offline= requires one or more units to perform a security review.");

        if (arg_threshold != 100 && !streq_ptr(argv[optind], "security"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --threshold= is only supported for security right now.");

        if (arg_runtime_scope == RUNTIME_SCOPE_GLOBAL && !streq_ptr(argv[optind], "unit-paths"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --global only makes sense with verb unit-paths.");

        if (streq_ptr(argv[optind], "cat-config") && arg_runtime_scope == RUNTIME_SCOPE_USER)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --user is not supported for cat-config right now.");

        if (arg_security_policy && !streq_ptr(argv[optind], "security"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --security-policy= is only supported for security.");

        if ((arg_root || arg_image) && (!STRPTR_IN_SET(argv[optind], "cat-config", "verify", "condition", "inspect-elf", "unit-gdb")) &&
           (!(streq_ptr(argv[optind], "security") && arg_offline)))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Options --root= and --image= are only supported for cat-config, verify, condition, unit-gdb, and security when used with --offline= right now.");

        /* Having both an image and a root is not supported by the code */
        if (arg_root && arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        if (arg_unit && !streq_ptr(argv[optind], "condition"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --unit= is only supported for condition");

        if (streq_ptr(argv[optind], "condition") && !arg_unit && optind >= argc - 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too few arguments for condition");

        if (streq_ptr(argv[optind], "condition") && arg_unit && optind < argc - 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No conditions can be passed if --unit= is used.");

        if (arg_table && !streq_ptr(argv[optind], "plot"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --table is only supported for plot right now.");

        if (arg_table && sd_json_format_enabled(arg_json_format_flags))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--table and --json= are mutually exclusive.");

        if (arg_capability != CAPABILITY_LITERAL && !streq_ptr(argv[optind], "capability"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --mask is only supported for capability.");

        if (arg_drm_device_path && !streq_ptr(argv[optind], "chid"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --drm-device is only supported for chid right now.");

        return 1; /* work to do */
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;

        static const Verb verbs[] = {
                { "help",               VERB_ANY, VERB_ANY, 0,            help                         },
                { "time",               VERB_ANY, 1,        VERB_DEFAULT, verb_time                    },
                { "blame",              VERB_ANY, 1,        0,            verb_blame                   },
                { "critical-chain",     VERB_ANY, VERB_ANY, 0,            verb_critical_chain          },
                { "plot",               VERB_ANY, 1,        0,            verb_plot                    },
                { "dot",                VERB_ANY, VERB_ANY, 0,            verb_dot                     },
                /* ↓ The following seven verbs are deprecated, from here … ↓ */
                { "log-level",          VERB_ANY, 2,        0,  verb_log_control        },
                { "log-target",         VERB_ANY, 2,        0,  verb_log_control        },
                { "set-log-level",      2,        2,        0,  verb_log_control        },
                { "get-log-level",      VERB_ANY, 1,        0,  verb_log_control        },
                { "set-log-target",     2,        2,        0,  verb_log_control        },
                { "get-log-target",     VERB_ANY, 1,        0,  verb_log_control        },
                { "service-watchdogs",  VERB_ANY, 2,        0,  verb_service_watchdogs  },
                /* ↑ … until here ↑ */
                { "dump",               VERB_ANY, VERB_ANY, 0,  verb_dump               },
                { "cat-config",         2,        VERB_ANY, 0,  verb_cat_config         },
                { "unit-files",         VERB_ANY, VERB_ANY, 0,  verb_unit_files         },
                { "unit-gdb",           2,        VERB_ANY, 0,  verb_unit_gdb           },
                { "unit-paths",         1,        1,        0,  verb_unit_paths         },
                { "unit-shell",         2,        VERB_ANY, 0,  verb_unit_shell         },
                { "exit-status",        VERB_ANY, VERB_ANY, 0,  verb_exit_status        },
                { "syscall-filter",     VERB_ANY, VERB_ANY, 0,  verb_syscall_filters    },
                { "capability",         VERB_ANY, VERB_ANY, 0,  verb_capabilities       },
                { "filesystems",        VERB_ANY, VERB_ANY, 0,  verb_filesystems        },
                { "condition",          VERB_ANY, VERB_ANY, 0,  verb_condition          },
                { "compare-versions",   3,        4,        0,  verb_compare_versions   },
                { "verify",             2,        VERB_ANY, 0,  verb_verify             },
                { "calendar",           2,        VERB_ANY, 0,  verb_calendar           },
                { "timestamp",          2,        VERB_ANY, 0,  verb_timestamp          },
                { "timespan",           2,        VERB_ANY, 0,  verb_timespan           },
                { "security",           VERB_ANY, VERB_ANY, 0,  verb_security           },
                { "inspect-elf",        2,        VERB_ANY, 0,  verb_elf_inspection     },
                { "dlopen-metadata",    2,        2,        0,  verb_dlopen_metadata    },
                { "malloc",             VERB_ANY, VERB_ANY, 0,  verb_malloc             },
                { "fdstore",            2,        VERB_ANY, 0,  verb_fdstore            },
                { "image-policy",       2,        2,        0,  verb_image_policy       },
                { "has-tpm2",           VERB_ANY, 1,        0,  verb_has_tpm2           },
                { "pcrs",               VERB_ANY, VERB_ANY, 0,  verb_pcrs               },
                { "srk",                VERB_ANY, 1,        0,  verb_srk                },
                { "architectures",      VERB_ANY, VERB_ANY, 0,  verb_architectures      },
                { "smbios11",           VERB_ANY, 1,        0,  verb_smbios11           },
                { "chid",               VERB_ANY, VERB_ANY, 0,  verb_chid               },
                { "transient-settings", 2,        VERB_ANY, 0,  verb_transient_settings },
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

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
