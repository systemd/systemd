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
#include "analyze-blame.h"
#include "analyze-calendar.h"
#include "analyze-capability.h"
#include "analyze-cat-config.h"
#include "analyze-condition.h"
#include "analyze-dot.h"
#include "analyze-dump.h"
#include "analyze-elf.h"
#include "analyze-exit-status.h"
#include "analyze-filesystems.h"
#include "analyze-log-control.h"
#include "analyze-plot.h"
#include "analyze-security.h"
#include "analyze-service-watchdogs.h"
#include "analyze-syscall-filter.h"
#include "analyze-time-data.h"
#include "analyze-timespan.h"
#include "analyze-timestamp.h"
#include "analyze-unit-paths.h"
#include "analyze-verify.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-map-properties.h"
#include "bus-unit-util.h"
#include "calendarspec.h"
#include "cap-list.h"
#include "capability-util.h"
#include "conf-files.h"
#include "copy.h"
#include "def.h"
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
#include "util.h"
#include "verb-log-control.h"
#include "verbs.h"
#include "version.h"

DotMode arg_dot = DEP_ALL;
char **arg_dot_from_patterns = NULL, **arg_dot_to_patterns = NULL;
static usec_t arg_fuzz = 0;
PagerFlags arg_pager_flags = 0;
BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
const char *arg_host = NULL;
UnitFileScope arg_scope = UNIT_FILE_SYSTEM;
static RecursiveErrors arg_recursive_errors = RECURSIVE_ERRORS_YES;
static bool arg_man = true;
static bool arg_generators = false;
char *arg_root = NULL;
static char *arg_image = NULL;
static char *arg_security_policy = NULL;
static bool arg_offline = false;
static unsigned arg_threshold = 100;
unsigned arg_iterations = 1;
usec_t arg_base_time = USEC_INFINITY;
static char *arg_unit = NULL;
static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
bool arg_quiet = false;
static char *arg_profile = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_dot_from_patterns, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_dot_to_patterns, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_security_policy, freep);
STATIC_DESTRUCTOR_REGISTER(arg_unit, freep);
STATIC_DESTRUCTOR_REGISTER(arg_profile, freep);

int acquire_bus(sd_bus **bus, bool *use_full_bus) {
        bool user = arg_scope != UNIT_FILE_SYSTEM;
        int r;

        if (use_full_bus && *use_full_bus) {
                r = bus_connect_transport(arg_transport, arg_host, user, bus);
                if (IN_SET(r, 0, -EHOSTDOWN))
                        return r;

                *use_full_bus = false;
        }

        return bus_connect_transport_systemd(arg_transport, arg_host, user, bus);
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

static int process_aliases(char *argv[], char *tempdir, char ***ret) {
        _cleanup_strv_free_ char **filenames = NULL;
        char **filename;
        int r;

        assert(argv);
        assert(tempdir);
        assert(ret);

        STRV_FOREACH(filename, strv_skip(argv, 1)) {
                _cleanup_free_ char *src = NULL, *dst = NULL, *base = NULL;
                const char *parse_arg;

                parse_arg = *filename;
                r = extract_first_word(&parse_arg, &src, ":", EXTRACT_DONT_COALESCE_SEPARATORS|EXTRACT_RETAIN_ESCAPE);
                if (r < 0)
                        return r;

                if (!parse_arg) {
                        r = strv_consume(&filenames, TAKE_PTR(src));
                        if (r < 0)
                                return r;

                        continue;
                }

                r = path_extract_filename(parse_arg, &base);
                if (r < 0)
                        return r;

                dst = path_join(tempdir, base);
                if (!dst)
                        return -ENOMEM;

                r = copy_file(src, dst, 0, 0644, 0, 0, COPY_REFLINK);
                if (r < 0)
                        return r;

                r = strv_consume(&filenames, TAKE_PTR(dst));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(filenames);
        return 0;
}

static int list_dependencies_print(
                const char *name,
                unsigned level,
                unsigned branches,
                bool last,
                UnitTimes *times,
                BootTimes *boot) {

        for (unsigned i = level; i != 0; i--)
                printf("%s", special_glyph(branches & (1 << (i-1)) ? SPECIAL_GLYPH_TREE_VERTICAL : SPECIAL_GLYPH_TREE_SPACE));

        printf("%s", special_glyph(last ? SPECIAL_GLYPH_TREE_RIGHT : SPECIAL_GLYPH_TREE_BRANCH));

        if (times) {
                if (times->time > 0)
                        printf("%s%s @%s +%s%s", ansi_highlight_red(), name,
                               FORMAT_TIMESPAN(times->activating - boot->userspace_time, USEC_PER_MSEC),
                               FORMAT_TIMESPAN(times->time, USEC_PER_MSEC), ansi_normal());
                else if (times->activated > boot->userspace_time)
                        printf("%s @%s", name, FORMAT_TIMESPAN(times->activated - boot->userspace_time, USEC_PER_MSEC));
                else
                        printf("%s", name);
        } else
                printf("%s", name);
        printf("\n");

        return 0;
}

static int list_dependencies_get_dependencies(sd_bus *bus, const char *name, char ***deps) {
        _cleanup_free_ char *path = NULL;

        assert(bus);
        assert(name);
        assert(deps);

        path = unit_dbus_path_from_name(name);
        if (!path)
                return -ENOMEM;

        return bus_get_unit_property_strv(bus, path, "After", deps);
}

static Hashmap *unit_times_hashmap;

static int list_dependencies_compare(char *const *a, char *const *b) {
        usec_t usa = 0, usb = 0;
        UnitTimes *times;

        times = hashmap_get(unit_times_hashmap, *a);
        if (times)
                usa = times->activated;
        times = hashmap_get(unit_times_hashmap, *b);
        if (times)
                usb = times->activated;

        return CMP(usb, usa);
}

static bool times_in_range(const UnitTimes *times, const BootTimes *boot) {
        return times && times->activated > 0 && times->activated <= boot->finish_time;
}

static int list_dependencies_one(sd_bus *bus, const char *name, unsigned level, char ***units, unsigned branches) {
        _cleanup_strv_free_ char **deps = NULL;
        char **c;
        int r;
        usec_t service_longest = 0;
        int to_print = 0;
        UnitTimes *times;
        BootTimes *boot;

        if (strv_extend(units, name))
                return log_oom();

        r = list_dependencies_get_dependencies(bus, name, &deps);
        if (r < 0)
                return r;

        typesafe_qsort(deps, strv_length(deps), list_dependencies_compare);

        r = acquire_boot_times(bus, &boot);
        if (r < 0)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c); /* lgtm [cpp/inconsistent-null-check] */
                if (times_in_range(times, boot) && times->activated >= service_longest)
                        service_longest = times->activated;
        }

        if (service_longest == 0)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c); /* lgtm [cpp/inconsistent-null-check] */
                if (times_in_range(times, boot) && service_longest - times->activated <= arg_fuzz)
                        to_print++;
        }

        if (!to_print)
                return r;

        STRV_FOREACH(c, deps) {
                times = hashmap_get(unit_times_hashmap, *c); /* lgtm [cpp/inconsistent-null-check] */
                if (!times_in_range(times, boot) || service_longest - times->activated > arg_fuzz)
                        continue;

                to_print--;

                r = list_dependencies_print(*c, level, branches, to_print == 0, times, boot);
                if (r < 0)
                        return r;

                if (strv_contains(*units, *c)) {
                        r = list_dependencies_print("...", level + 1, (branches << 1) | (to_print ? 1 : 0),
                                                    true, NULL, boot);
                        if (r < 0)
                                return r;
                        continue;
                }

                r = list_dependencies_one(bus, *c, level + 1, units, (branches << 1) | (to_print ? 1 : 0));
                if (r < 0)
                        return r;

                if (to_print == 0)
                        break;
        }
        return 0;
}

static int list_dependencies(sd_bus *bus, const char *name) {
        _cleanup_strv_free_ char **units = NULL;
        UnitTimes *times;
        int r;
        const char *id;
        _cleanup_free_ char *path = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        BootTimes *boot;

        assert(bus);

        path = unit_dbus_path_from_name(name);
        if (!path)
                return -ENOMEM;

        r = sd_bus_get_property(
                        bus,
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit",
                        "Id",
                        &error,
                        &reply,
                        "s");
        if (r < 0)
                return log_error_errno(r, "Failed to get ID: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "s", &id);
        if (r < 0)
                return bus_log_parse_error(r);

        times = hashmap_get(unit_times_hashmap, id);

        r = acquire_boot_times(bus, &boot);
        if (r < 0)
                return r;

        if (times) {
                if (times->time)
                        printf("%s%s +%s%s\n", ansi_highlight_red(), id,
                               FORMAT_TIMESPAN(times->time, USEC_PER_MSEC), ansi_normal());
                else if (times->activated > boot->userspace_time)
                        printf("%s @%s\n", id,
                               FORMAT_TIMESPAN(times->activated - boot->userspace_time, USEC_PER_MSEC));
                else
                        printf("%s\n", id);
        }

        return list_dependencies_one(bus, name, 0, &units, 0);
}

static int analyze_critical_chain(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(unit_times_free_arrayp) UnitTimes *times = NULL;
        Hashmap *h;
        int n, r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        n = acquire_time_data(bus, &times);
        if (n <= 0)
                return n;

        h = hashmap_new(&string_hash_ops);
        if (!h)
                return log_oom();

        for (UnitTimes *u = times; u->has_data; u++) {
                r = hashmap_put(h, u->name, u);
                if (r < 0)
                        return log_error_errno(r, "Failed to add entry to hashmap: %m");
        }
        unit_times_hashmap = h;

        pager_open(arg_pager_flags);

        puts("The time when unit became active or started is printed after the \"@\" character.\n"
             "The time the unit took to start is printed after the \"+\" character.\n");

        if (argc > 1) {
                char **name;
                STRV_FOREACH(name, strv_skip(argv, 1))
                        list_dependencies(bus, *name);
        } else
                list_dependencies(bus, SPECIAL_DEFAULT_TARGET);

        h = hashmap_free(h);
        return 0;
}

static int analyze_time(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *buf = NULL;
        int r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        r = pretty_boot_time(bus, &buf);
        if (r < 0)
                return r;

        puts(buf);
        return 0;
}

static bool strv_fnmatch_strv_or_empty(char* const* patterns, char **strv, int flags) {
        char **s;
        STRV_FOREACH(s, strv)
                if (strv_fnmatch_or_empty(patterns, *s, flags))
                        return true;

        return false;
}

static int do_unit_files(int argc, char *argv[], void *userdata) {
        _cleanup_(lookup_paths_free) LookupPaths lp = {};
        _cleanup_hashmap_free_ Hashmap *unit_ids = NULL;
        _cleanup_hashmap_free_ Hashmap *unit_names = NULL;
        char **patterns = strv_skip(argv, 1);
        const char *k, *dst;
        char **v;
        int r;

        r = lookup_paths_init(&lp, arg_scope, 0, NULL);
        if (r < 0)
                return log_error_errno(r, "lookup_paths_init() failed: %m");

        r = unit_file_build_name_map(&lp, NULL, &unit_ids, &unit_names, NULL);
        if (r < 0)
                return log_error_errno(r, "unit_file_build_name_map() failed: %m");

        HASHMAP_FOREACH_KEY(dst, k, unit_ids) {
                if (!strv_fnmatch_or_empty(patterns, k, FNM_NOESCAPE) &&
                    !strv_fnmatch_or_empty(patterns, dst, FNM_NOESCAPE))
                        continue;

                printf("ids: %s → %s\n", k, dst);
        }

        HASHMAP_FOREACH_KEY(v, k, unit_names) {
                if (!strv_fnmatch_or_empty(patterns, k, FNM_NOESCAPE) &&
                    !strv_fnmatch_strv_or_empty(patterns, v, FNM_NOESCAPE))
                        continue;

                _cleanup_free_ char *j = strv_join(v, ", ");
                printf("aliases: %s ← %s\n", k, j);
        }

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

static int do_condition(int argc, char *argv[], void *userdata) {
        return verify_conditions(strv_skip(argv, 1), arg_scope, arg_unit, arg_root);
}

static int do_verify(int argc, char *argv[], void *userdata) {
        _cleanup_strv_free_ char **filenames = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *tempdir = NULL;
        int r;

        r = mkdtemp_malloc("/tmp/systemd-analyze-XXXXXX", &tempdir);
        if (r < 0)
                return log_error_errno(r, "Failed to setup working directory: %m");

        r = process_aliases(argv, tempdir, &filenames);
        if (r < 0)
                return log_error_errno(r, "Couldn't process aliases: %m");

        return verify_units(filenames, arg_scope, arg_man, arg_generators, arg_recursive_errors, arg_root);
}

static int do_security(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *policy = NULL;
        int r;
        unsigned line, column;

        if (!arg_offline) {
                r = acquire_bus(&bus, NULL);
                if (r < 0)
                        return bus_log_connect_error(r, arg_transport);
        }

        pager_open(arg_pager_flags);

        if (arg_security_policy) {
                r = json_parse_file(/*f=*/ NULL, arg_security_policy, /*flags=*/ 0, &policy, &line, &column);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse '%s' at %u:%u: %m", arg_security_policy, line, column);
        } else {
                _cleanup_fclose_ FILE *f = NULL;
                _cleanup_free_ char *pp = NULL;

                r = search_and_fopen_nulstr("systemd-analyze-security.policy", "re", /*root=*/ NULL, CONF_PATHS_NULSTR("systemd"), &f, &pp);
                if (r < 0 && r != -ENOENT)
                        return r;

                if (f) {
                        r = json_parse_file(f, pp, /*flags=*/ 0, &policy, &line, &column);
                        if (r < 0)
                                return log_error_errno(r, "[%s:%u:%u] Failed to parse JSON policy: %m", pp, line, column);
                }
        }

        return analyze_security(bus,
                                strv_skip(argv, 1),
                                policy,
                                arg_scope,
                                arg_man,
                                arg_generators,
                                arg_offline,
                                arg_threshold,
                                arg_root,
                                arg_profile,
                                arg_json_format_flags,
                                arg_pager_flags,
                                /*flags=*/ 0);
}

static int do_elf_inspection(int argc, char *argv[], void *userdata) {
        pager_open(arg_pager_flags);

        return analyze_elf(strv_skip(argv, 1), arg_json_format_flags);
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
               "  dump                       Output state serialization of service\n"
               "                             manager\n"
               "  cat-config                 Show configuration file and drop-ins\n"
               "  unit-files                 List files and symlinks for units\n"
               "  unit-paths                 List load directories for units\n"
               "  exit-status [STATUS...]    List exit status definitions\n"
               "  capability [CAP...]        List capability definitions\n"
               "  syscall-filter [NAME...]   List syscalls in seccomp filters\n"
               "  filesystems [NAME...]      List known filesystems\n"
               "  condition CONDITION...     Evaluate conditions and asserts\n"
               "  verify FILE...             Check unit files for correctness\n"
               "  calendar SPEC...           Validate repetitive calendar time\n"
               "                             events\n"
               "  timestamp TIMESTAMP...     Validate a timestamp\n"
               "  timespan SPAN...           Validate a time span\n"
               "  security [UNIT...]         Analyze security of unit\n"
               "  inspect-elf FILE...        Parse and print ELF package metadata\n"
               "\nOptions:\n"
               "     --recursive-errors=MODE Control which units are verified\n"
               "     --offline=BOOL          Perform a security review on unit file(s)\n"
               "     --threshold=N           Exit with a non-zero status when overall\n"
               "                             exposure level is over threshold value\n"
               "     --security-policy=PATH  Use custom JSON security policy instead\n"
               "                             of built-in one\n"
               "     --json=pretty|short|off Generate JSON output of the security\n"
               "                             analysis table\n"
               "     --no-pager              Do not pipe output into a pager\n"
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
               "  -h --help                  Show this help\n"
               "     --version               Show package version\n"
               "  -q --quiet                 Do not emit hints\n"
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
        };

        static const struct option options[] = {
                { "help",             no_argument,       NULL, 'h'                  },
                { "version",          no_argument,       NULL, ARG_VERSION          },
                { "quiet",            no_argument,       NULL, 'q'                  },
                { "order",            no_argument,       NULL, ARG_ORDER            },
                { "require",          no_argument,       NULL, ARG_REQUIRE          },
                { "root",             required_argument, NULL, ARG_ROOT             },
                { "image",            required_argument, NULL, ARG_IMAGE            },
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
                {}
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hH:M:U:", options, NULL)) >= 0)
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

                case ARG_SYSTEM:
                        arg_scope = UNIT_FILE_SYSTEM;
                        break;

                case ARG_USER:
                        arg_scope = UNIT_FILE_USER;
                        break;

                case ARG_GLOBAL:
                        arg_scope = UNIT_FILE_GLOBAL;
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
                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_offline && !streq_ptr(argv[optind], "security"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --offline= is only supported for security right now.");

        if (arg_json_format_flags != JSON_FORMAT_OFF && !STRPTR_IN_SET(argv[optind], "security", "inspect-elf"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --json= is only supported for security and inspect-elf right now.");

        if (arg_threshold != 100 && !streq_ptr(argv[optind], "security"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --threshold= is only supported for security right now.");

        if (arg_scope == UNIT_FILE_GLOBAL &&
            !STR_IN_SET(argv[optind] ?: "time", "dot", "unit-paths", "verify"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Option --global only makes sense with verbs dot, unit-paths, verify.");

        if (streq_ptr(argv[optind], "cat-config") && arg_scope == UNIT_FILE_USER)
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

        return 1; /* work to do */
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *decrypted_image = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *unlink_dir = NULL;

        static const Verb verbs[] = {
                { "help",              VERB_ANY, VERB_ANY, 0,            help                   },
                { "time",              VERB_ANY, 1,        VERB_DEFAULT, analyze_time           },
                { "blame",             VERB_ANY, 1,        0,            analyze_blame          },
                { "critical-chain",    VERB_ANY, VERB_ANY, 0,            analyze_critical_chain },
                { "plot",              VERB_ANY, 1,        0,            analyze_plot           },
                { "dot",               VERB_ANY, VERB_ANY, 0,            dot                    },
                /* ↓ The following seven verbs are deprecated, from here … ↓ */
                { "log-level",         VERB_ANY, 2,        0,            verb_log_control       },
                { "log-target",        VERB_ANY, 2,        0,            verb_log_control       },
                { "set-log-level",     2,        2,        0,            verb_log_control       },
                { "get-log-level",     VERB_ANY, 1,        0,            verb_log_control       },
                { "set-log-target",    2,        2,        0,            verb_log_control       },
                { "get-log-target",    VERB_ANY, 1,        0,            verb_log_control       },
                { "service-watchdogs", VERB_ANY, 2,        0,            service_watchdogs      },
                /* ↑ … until here ↑ */
                { "dump",              VERB_ANY, 1,        0,            dump                   },
                { "cat-config",        2,        VERB_ANY, 0,            cat_config             },
                { "unit-files",        VERB_ANY, VERB_ANY, 0,            do_unit_files          },
                { "unit-paths",        1,        1,        0,            dump_unit_paths        },
                { "exit-status",       VERB_ANY, VERB_ANY, 0,            dump_exit_status       },
                { "syscall-filter",    VERB_ANY, VERB_ANY, 0,            dump_syscall_filters   },
                { "capability",        VERB_ANY, VERB_ANY, 0,            dump_capabilities      },
                { "filesystems",       VERB_ANY, VERB_ANY, 0,            dump_filesystems       },
                { "condition",         VERB_ANY, VERB_ANY, 0,            do_condition           },
                { "verify",            2,        VERB_ANY, 0,            do_verify              },
                { "calendar",          2,        VERB_ANY, 0,            test_calendar          },
                { "timestamp",         2,        VERB_ANY, 0,            test_timestamp         },
                { "timespan",          2,        VERB_ANY, 0,            dump_timespan          },
                { "security",          VERB_ANY, VERB_ANY, 0,            do_security            },
                { "inspect-elf",       2,        VERB_ANY, 0,            do_elf_inspection      },
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
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_READ_ONLY,
                                &unlink_dir,
                                &loop_device,
                                &decrypted_image);
                if (r < 0)
                        return r;

                arg_root = strdup(unlink_dir);
                if (!arg_root)
                        return log_oom();
        }

        return dispatch_verb(argc, argv, verbs, NULL);
}

DEFINE_MAIN_FUNCTION(run);
