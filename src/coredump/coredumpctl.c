/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <getopt.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-journal.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "compress.h"
#include "def.h"
#include "fd-util.h"
#include "fs-util.h"
#include "journal-internal.h"
#include "journal-util.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "pager.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "sigbus.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "util.h"
#include "verbs.h"

#define SHORT_BUS_CALL_TIMEOUT_USEC (3 * USEC_PER_SEC)

static usec_t arg_since = USEC_INFINITY, arg_until = USEC_INFINITY;
static const char* arg_field = NULL;
static const char *arg_debugger = NULL;
static const char *arg_directory = NULL;
static PagerFlags arg_pager_flags = 0;
static int arg_no_legend = false;
static int arg_one = false;
static const char* arg_output = NULL;
static bool arg_reverse = false;
static bool arg_quiet = false;

static int add_match(sd_journal *j, const char *match) {
        _cleanup_free_ char *p = NULL;
        const char* prefix, *pattern;
        pid_t pid;
        int r;

        if (strchr(match, '='))
                prefix = "";
        else if (strchr(match, '/')) {
                r = path_make_absolute_cwd(match, &p);
                if (r < 0)
                        return log_error_errno(r, "path_make_absolute_cwd(\"%s\"): %m", match);

                match = p;
                prefix = "COREDUMP_EXE=";
        } else if (parse_pid(match, &pid) >= 0)
                prefix = "COREDUMP_PID=";
        else
                prefix = "COREDUMP_COMM=";

        pattern = strjoina(prefix, match);
        log_debug("Adding match: %s", pattern);
        r = sd_journal_add_match(j, pattern, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to add match \"%s\": %m", match);

        return 0;
}

static int add_matches(sd_journal *j, char **matches) {
        char **match;
        int r;

        r = sd_journal_add_match(j, "MESSAGE_ID=" SD_MESSAGE_COREDUMP_STR, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to add match \"%s\": %m", "MESSAGE_ID=" SD_MESSAGE_COREDUMP_STR);

        r = sd_journal_add_match(j, "MESSAGE_ID=" SD_MESSAGE_BACKTRACE_STR, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to add match \"%s\": %m", "MESSAGE_ID=" SD_MESSAGE_BACKTRACE_STR);

        STRV_FOREACH(match, matches) {
                r = add_match(j, *match);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int acquire_journal(sd_journal **ret, char **matches) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        int r;

        assert(ret);

        if (arg_directory) {
                r = sd_journal_open_directory(&j, arg_directory, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to open journals in directory: %s: %m", arg_directory);
        } else {
                r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
                if (r < 0)
                        return log_error_errno(r, "Failed to open journal: %m");
        }

        r = journal_access_check_and_warn(j, arg_quiet, true);
        if (r < 0)
                return r;

        r = add_matches(j, matches);
        if (r < 0)
                return r;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *filter;

                filter = journal_make_match_string(j);
                log_debug("Journal filter: %s", filter);
        }

        *ret = TAKE_PTR(j);

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("coredumpctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...]\n\n"
               "List or retrieve coredumps from the journal.\n\n"
               "Flags:\n"
               "  -h --help              Show this help\n"
               "     --version           Print version string\n"
               "     --no-pager          Do not pipe output into a pager\n"
               "     --no-legend         Do not print the column headers\n"
               "     --debugger=DEBUGGER Use the given debugger\n"
               "  -1                     Show information about most recent entry only\n"
               "  -S --since=DATE        Only print coredumps since the date\n"
               "  -U --until=DATE        Only print coredumps until the date\n"
               "  -r --reverse           Show the newest entries first\n"
               "  -F --field=FIELD       List all values a certain field takes\n"
               "  -o --output=FILE       Write output to FILE\n"
               "  -D --directory=DIR     Use journal files from directory\n\n"
               "  -q --quiet             Do not show info messages and privilege warning\n"
               "Commands:\n"
               "  list [MATCHES...]  List available coredumps (default)\n"
               "  info [MATCHES...]  Show detailed information about one or more coredumps\n"
               "  dump [MATCHES...]  Print first matching coredump to stdout\n"
               "  debug [MATCHES...] Start a debugger for the first matching coredump\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_DEBUGGER,
        };

        int c, r;

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'           },
                { "version" ,     no_argument,       NULL, ARG_VERSION   },
                { "no-pager",     no_argument,       NULL, ARG_NO_PAGER  },
                { "no-legend",    no_argument,       NULL, ARG_NO_LEGEND },
                { "debugger",     required_argument, NULL, ARG_DEBUGGER  },
                { "output",       required_argument, NULL, 'o'           },
                { "field",        required_argument, NULL, 'F'           },
                { "directory",    required_argument, NULL, 'D'           },
                { "reverse",      no_argument,       NULL, 'r'           },
                { "since",        required_argument, NULL, 'S'           },
                { "until",        required_argument, NULL, 'U'           },
                { "quiet",        no_argument,       NULL, 'q'           },
                {}
        };

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ho:F:1D:rS:U:q", options, NULL)) >= 0)
                switch(c) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_no_legend = true;
                        break;

                case ARG_DEBUGGER:
                        arg_debugger = optarg;
                        break;

                case 'o':
                        if (arg_output)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot set output more than once.");

                        arg_output = optarg;
                        break;

                case 'S':
                        r = parse_timestamp(optarg, &arg_since);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timestamp '%s': %m", optarg);
                        break;

                case 'U':
                        r = parse_timestamp(optarg, &arg_until);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timestamp '%s': %m", optarg);
                        break;

                case 'F':
                        if (arg_field)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot use --field/-F more than once.");
                        arg_field = optarg;
                        break;

                case '1':
                        arg_one = true;
                        break;

                case 'D':
                        arg_directory = optarg;
                        break;

                case 'r':
                        arg_reverse = true;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (arg_since != USEC_INFINITY && arg_until != USEC_INFINITY &&
            arg_since > arg_until)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--since= must be before --until=.");

        return 1;
}

static int retrieve(const void *data,
                    size_t len,
                    const char *name,
                    char **var) {

        size_t ident;
        char *v;

        ident = strlen(name) + 1; /* name + "=" */

        if (len < ident)
                return 0;

        if (memcmp(data, name, ident - 1) != 0)
                return 0;

        if (((const char*) data)[ident - 1] != '=')
                return 0;

        v = strndup((const char*)data + ident, len - ident);
        if (!v)
                return log_oom();

        free_and_replace(*var, v);
        return 1;
}

static int print_field(FILE* file, sd_journal *j) {
        const void *d;
        size_t l;

        assert(file);
        assert(j);

        assert(arg_field);

        /* A (user-specified) field may appear more than once for a given entry.
         * We will print all of the occurrences.
         * This is different below for fields that systemd-coredump uses,
         * because they cannot meaningfully appear more than once.
         */
        SD_JOURNAL_FOREACH_DATA(j, d, l) {
                _cleanup_free_ char *value = NULL;
                int r;

                r = retrieve(d, l, arg_field, &value);
                if (r < 0)
                        return r;
                if (r > 0)
                        fprintf(file, "%s\n", value);
        }

        return 0;
}

#define RETRIEVE(d, l, name, arg)                    \
        {                                            \
                int _r = retrieve(d, l, name, &arg); \
                if (_r < 0)                          \
                        return _r;                   \
                if (_r > 0)                          \
                        continue;                    \
        }

static int print_list(FILE* file, sd_journal *j, int had_legend) {
        _cleanup_free_ char
                *mid = NULL, *pid = NULL, *uid = NULL, *gid = NULL,
                *sgnl = NULL, *exe = NULL, *comm = NULL, *cmdline = NULL,
                *filename = NULL, *truncated = NULL, *coredump = NULL;
        const void *d;
        size_t l;
        usec_t t;
        char buf[FORMAT_TIMESTAMP_MAX];
        int r;
        const char *present;
        bool normal_coredump;

        assert(file);
        assert(j);

        SD_JOURNAL_FOREACH_DATA(j, d, l) {
                RETRIEVE(d, l, "MESSAGE_ID", mid);
                RETRIEVE(d, l, "COREDUMP_PID", pid);
                RETRIEVE(d, l, "COREDUMP_UID", uid);
                RETRIEVE(d, l, "COREDUMP_GID", gid);
                RETRIEVE(d, l, "COREDUMP_SIGNAL", sgnl);
                RETRIEVE(d, l, "COREDUMP_EXE", exe);
                RETRIEVE(d, l, "COREDUMP_COMM", comm);
                RETRIEVE(d, l, "COREDUMP_CMDLINE", cmdline);
                RETRIEVE(d, l, "COREDUMP_FILENAME", filename);
                RETRIEVE(d, l, "COREDUMP_TRUNCATED", truncated);
                RETRIEVE(d, l, "COREDUMP", coredump);
        }

        if (!pid && !uid && !gid && !sgnl && !exe && !comm && !cmdline && !filename) {
                log_warning("Empty coredump log entry");
                return -EINVAL;
        }

        r = sd_journal_get_realtime_usec(j, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to get realtime timestamp: %m");

        format_timestamp(buf, sizeof(buf), t);

        if (!had_legend && !arg_no_legend)
                fprintf(file, "%-*s %*s %*s %*s %*s %-*s %s\n",
                        FORMAT_TIMESTAMP_WIDTH, "TIME",
                        6, "PID",
                        5, "UID",
                        5, "GID",
                        3, "SIG",
                        9, "COREFILE",
                           "EXE");

        normal_coredump = streq_ptr(mid, SD_MESSAGE_COREDUMP_STR);

        if (filename)
                if (access(filename, R_OK) == 0)
                        present = "present";
                else if (errno == ENOENT)
                        present = "missing";
                else
                        present = "error";
        else if (coredump)
                present = "journal";
        else if (normal_coredump)
                present = "none";
        else
                present = "-";

        if (STR_IN_SET(present, "present", "journal") && truncated && parse_boolean(truncated) > 0)
                present = "truncated";

        fprintf(file, "%-*s %*s %*s %*s %*s %-*s %s\n",
                FORMAT_TIMESTAMP_WIDTH, buf,
                6, strna(pid),
                5, strna(uid),
                5, strna(gid),
                3, normal_coredump ? strna(sgnl) : "-",
                9, present,
                strna(exe ?: (comm ?: cmdline)));

        return 0;
}

static int print_info(FILE *file, sd_journal *j, bool need_space) {
        _cleanup_free_ char
                *mid = NULL, *pid = NULL, *uid = NULL, *gid = NULL,
                *sgnl = NULL, *exe = NULL, *comm = NULL, *cmdline = NULL,
                *unit = NULL, *user_unit = NULL, *session = NULL,
                *boot_id = NULL, *machine_id = NULL, *hostname = NULL,
                *slice = NULL, *cgroup = NULL, *owner_uid = NULL,
                *message = NULL, *timestamp = NULL, *filename = NULL,
                *truncated = NULL, *coredump = NULL;
        const void *d;
        size_t l;
        bool normal_coredump;
        int r;

        assert(file);
        assert(j);

        SD_JOURNAL_FOREACH_DATA(j, d, l) {
                RETRIEVE(d, l, "MESSAGE_ID", mid);
                RETRIEVE(d, l, "COREDUMP_PID", pid);
                RETRIEVE(d, l, "COREDUMP_UID", uid);
                RETRIEVE(d, l, "COREDUMP_GID", gid);
                RETRIEVE(d, l, "COREDUMP_SIGNAL", sgnl);
                RETRIEVE(d, l, "COREDUMP_EXE", exe);
                RETRIEVE(d, l, "COREDUMP_COMM", comm);
                RETRIEVE(d, l, "COREDUMP_CMDLINE", cmdline);
                RETRIEVE(d, l, "COREDUMP_UNIT", unit);
                RETRIEVE(d, l, "COREDUMP_USER_UNIT", user_unit);
                RETRIEVE(d, l, "COREDUMP_SESSION", session);
                RETRIEVE(d, l, "COREDUMP_OWNER_UID", owner_uid);
                RETRIEVE(d, l, "COREDUMP_SLICE", slice);
                RETRIEVE(d, l, "COREDUMP_CGROUP", cgroup);
                RETRIEVE(d, l, "COREDUMP_TIMESTAMP", timestamp);
                RETRIEVE(d, l, "COREDUMP_FILENAME", filename);
                RETRIEVE(d, l, "COREDUMP_TRUNCATED", truncated);
                RETRIEVE(d, l, "COREDUMP", coredump);
                RETRIEVE(d, l, "_BOOT_ID", boot_id);
                RETRIEVE(d, l, "_MACHINE_ID", machine_id);
                RETRIEVE(d, l, "_HOSTNAME", hostname);
                RETRIEVE(d, l, "MESSAGE", message);
        }

        if (need_space)
                fputs("\n", file);

        normal_coredump = streq_ptr(mid, SD_MESSAGE_COREDUMP_STR);

        if (comm)
                fprintf(file,
                        "           PID: %s%s%s (%s)\n",
                        ansi_highlight(), strna(pid), ansi_normal(), comm);
        else
                fprintf(file,
                        "           PID: %s%s%s\n",
                        ansi_highlight(), strna(pid), ansi_normal());

        if (uid) {
                uid_t n;

                if (parse_uid(uid, &n) >= 0) {
                        _cleanup_free_ char *u = NULL;

                        u = uid_to_name(n);
                        fprintf(file,
                                "           UID: %s (%s)\n",
                                uid, u);
                } else {
                        fprintf(file,
                                "           UID: %s\n",
                                uid);
                }
        }

        if (gid) {
                gid_t n;

                if (parse_gid(gid, &n) >= 0) {
                        _cleanup_free_ char *g = NULL;

                        g = gid_to_name(n);
                        fprintf(file,
                                "           GID: %s (%s)\n",
                                gid, g);
                } else {
                        fprintf(file,
                                "           GID: %s\n",
                                gid);
                }
        }

        if (sgnl) {
                int sig;
                const char *name = normal_coredump ? "Signal" : "Reason";

                if (normal_coredump && safe_atoi(sgnl, &sig) >= 0)
                        fprintf(file, "        %s: %s (%s)\n", name, sgnl, signal_to_string(sig));
                else
                        fprintf(file, "        %s: %s\n", name, sgnl);
        }

        if (timestamp) {
                usec_t u;

                r = safe_atou64(timestamp, &u);
                if (r >= 0) {
                        char absolute[FORMAT_TIMESTAMP_MAX], relative[FORMAT_TIMESPAN_MAX];

                        fprintf(file,
                                "     Timestamp: %s (%s)\n",
                                format_timestamp(absolute, sizeof(absolute), u),
                                format_timestamp_relative(relative, sizeof(relative), u));

                } else
                        fprintf(file, "     Timestamp: %s\n", timestamp);
        }

        if (cmdline)
                fprintf(file, "  Command Line: %s\n", cmdline);
        if (exe)
                fprintf(file, "    Executable: %s%s%s\n", ansi_highlight(), exe, ansi_normal());
        if (cgroup)
                fprintf(file, " Control Group: %s\n", cgroup);
        if (unit)
                fprintf(file, "          Unit: %s\n", unit);
        if (user_unit)
                fprintf(file, "     User Unit: %s\n", user_unit);
        if (slice)
                fprintf(file, "         Slice: %s\n", slice);
        if (session)
                fprintf(file, "       Session: %s\n", session);
        if (owner_uid) {
                uid_t n;

                if (parse_uid(owner_uid, &n) >= 0) {
                        _cleanup_free_ char *u = NULL;

                        u = uid_to_name(n);
                        fprintf(file,
                                "     Owner UID: %s (%s)\n",
                                owner_uid, u);
                } else {
                        fprintf(file,
                                "     Owner UID: %s\n",
                                owner_uid);
                }
        }
        if (boot_id)
                fprintf(file, "       Boot ID: %s\n", boot_id);
        if (machine_id)
                fprintf(file, "    Machine ID: %s\n", machine_id);
        if (hostname)
                fprintf(file, "      Hostname: %s\n", hostname);

        if (filename) {
                bool inacc, trunc;

                inacc = access(filename, R_OK) < 0;
                trunc = truncated && parse_boolean(truncated) > 0;

                if (inacc || trunc)
                        fprintf(file, "       Storage: %s%s (%s%s%s)%s\n",
                                ansi_highlight_red(),
                                filename,
                                inacc ? "inaccessible" : "",
                                inacc && trunc ? ", " : "",
                                trunc ? "truncated" : "",
                                ansi_normal());
                else
                        fprintf(file, "       Storage: %s\n", filename);
        }

        else if (coredump)
                fprintf(file, "       Storage: journal\n");
        else
                fprintf(file, "       Storage: none\n");

        if (message) {
                _cleanup_free_ char *m = NULL;

                m = strreplace(message, "\n", "\n                ");

                fprintf(file, "       Message: %s\n", strstrip(m ?: message));
        }

        return 0;
}

static int focus(sd_journal *j) {
        int r;

        r = sd_journal_seek_tail(j);
        if (r == 0)
                r = sd_journal_previous(j);
        if (r < 0)
                return log_error_errno(r, "Failed to search journal: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH),
                                       "No match found.");
        return r;
}

static int print_entry(sd_journal *j, unsigned n_found, bool verb_is_info) {
        assert(j);

        if (verb_is_info)
                return print_info(stdout, j, n_found);
        else if (arg_field)
                return print_field(stdout, j);
        else
                return print_list(stdout, j, n_found);
}

static int dump_list(int argc, char **argv, void *userdata) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        unsigned n_found = 0;
        bool verb_is_info;
        int r;

        verb_is_info = (argc >= 1 && streq(argv[0], "info"));

        r = acquire_journal(&j, argv + 1);
        if (r < 0)
                return r;

        (void) pager_open(arg_pager_flags);

        /* The coredumps are likely to compressed, and for just
         * listing them we don't need to decompress them, so let's
         * pick a fairly low data threshold here */
        sd_journal_set_data_threshold(j, 4096);

        /* "info" without pattern implies "-1" */
        if (arg_one || (verb_is_info && argc == 1)) {
                r = focus(j);
                if (r < 0)
                        return r;

                return print_entry(j, 0, verb_is_info);
        } else {
                if (arg_since != USEC_INFINITY && !arg_reverse)
                        r = sd_journal_seek_realtime_usec(j, arg_since);
                else if (arg_until != USEC_INFINITY && arg_reverse)
                        r = sd_journal_seek_realtime_usec(j, arg_until);
                else if (arg_reverse)
                        r = sd_journal_seek_tail(j);
                else
                        r = sd_journal_seek_head(j);
                if (r < 0)
                        return log_error_errno(r, "Failed to seek to date: %m");

                for (;;) {
                        if (!arg_reverse)
                                r = sd_journal_next(j);
                        else
                                r = sd_journal_previous(j);

                        if (r < 0)
                                return log_error_errno(r, "Failed to iterate through journal: %m");

                        if (r == 0)
                                break;

                        if (arg_until != USEC_INFINITY && !arg_reverse) {
                                usec_t usec;

                                r = sd_journal_get_realtime_usec(j, &usec);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to determine timestamp: %m");
                                if (usec > arg_until)
                                        continue;
                        }

                        if (arg_since != USEC_INFINITY && arg_reverse) {
                                usec_t usec;

                                r = sd_journal_get_realtime_usec(j, &usec);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to determine timestamp: %m");
                                if (usec < arg_since)
                                        continue;
                        }

                        r = print_entry(j, n_found++, verb_is_info);
                        if (r < 0)
                                return r;
                }

                if (!arg_field && n_found <= 0) {
                        if (!arg_quiet)
                                log_notice("No coredumps found.");
                        return -ESRCH;
                }
        }

        return 0;
}

static int save_core(sd_journal *j, FILE *file, char **path, bool *unlink_temp) {
        const char *data;
        _cleanup_free_ char *filename = NULL;
        size_t len;
        int r, fd;
        _cleanup_close_ int fdt = -1;
        char *temp = NULL;

        assert(!(file && path));         /* At most one can be specified */
        assert(!!path == !!unlink_temp); /* Those must be specified together */

        /* Look for a coredump on disk first. */
        r = sd_journal_get_data(j, "COREDUMP_FILENAME", (const void**) &data, &len);
        if (r == 0) {
                r = retrieve(data, len, "COREDUMP_FILENAME", &filename);
                if (r < 0)
                        return r;
                assert(r > 0);

                if (access(filename, R_OK) < 0)
                        return log_error_errno(errno, "File \"%s\" is not readable: %m", filename);

                if (path && !endswith(filename, ".xz") && !endswith(filename, ".lz4")) {
                        *path = TAKE_PTR(filename);

                        return 0;
                }

        } else {
                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to retrieve COREDUMP_FILENAME field: %m");
                /* Check that we can have a COREDUMP field. We still haven't set a high
                 * data threshold, so we'll get a few kilobytes at most.
                 */

                r = sd_journal_get_data(j, "COREDUMP", (const void**) &data, &len);
                if (r == -ENOENT)
                        return log_error_errno(r, "Coredump entry has no core attached (neither internally in the journal nor externally on disk).");
                if (r < 0)
                        return log_error_errno(r, "Failed to retrieve COREDUMP field: %m");
        }

        if (path) {
                const char *vt;

                /* Create a temporary file to write the uncompressed core to. */

                r = var_tmp_dir(&vt);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire temporary directory path: %m");

                temp = path_join(vt, "coredump-XXXXXX");
                if (!temp)
                        return log_oom();

                fdt = mkostemp_safe(temp);
                if (fdt < 0)
                        return log_error_errno(fdt, "Failed to create temporary file: %m");
                log_debug("Created temporary file %s", temp);

                fd = fdt;
        } else {
                /* If neither path or file are specified, we will write to stdout. Let's now check
                 * if stdout is connected to a tty. We checked that the file exists, or that the
                 * core might be stored in the journal. In this second case, if we found the entry,
                 * in all likelihood we will be able to access the COREDUMP= field.  In either case,
                 * we stop before doing any "real" work, i.e. before starting decompression or
                 * reading from the file or creating temporary files.
                 */
                if (!file) {
                        if (on_tty())
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY),
                                                       "Refusing to dump core to tty"
                                                       " (use shell redirection or specify --output).");
                        file = stdout;
                }

                fd = fileno(file);
        }

        if (filename) {
#if HAVE_XZ || HAVE_LZ4
                _cleanup_close_ int fdf;

                fdf = open(filename, O_RDONLY | O_CLOEXEC);
                if (fdf < 0) {
                        r = log_error_errno(errno, "Failed to open %s: %m", filename);
                        goto error;
                }

                r = decompress_stream(filename, fdf, fd, -1);
                if (r < 0) {
                        log_error_errno(r, "Failed to decompress %s: %m", filename);
                        goto error;
                }
#else
                log_error("Cannot decompress file. Compiled without compression support.");
                r = -EOPNOTSUPP;
                goto error;
#endif
        } else {
                ssize_t sz;

                /* We want full data, nothing truncated. */
                sd_journal_set_data_threshold(j, 0);

                r = sd_journal_get_data(j, "COREDUMP", (const void**) &data, &len);
                if (r < 0)
                        return log_error_errno(r, "Failed to retrieve COREDUMP field: %m");

                assert(len >= 9);
                data += 9;
                len -= 9;

                sz = write(fd, data, len);
                if (sz < 0) {
                        r = log_error_errno(errno, "Failed to write output: %m");
                        goto error;
                }
                if (sz != (ssize_t) len) {
                        log_error("Short write to output.");
                        r = -EIO;
                        goto error;
                }
        }

        if (temp) {
                *path = temp;
                *unlink_temp = true;
        }
        return 0;

error:
        if (temp) {
                (void) unlink(temp);
                log_debug("Removed temporary file %s", temp);
        }
        return r;
}

static int dump_core(int argc, char **argv, void *userdata) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        if (arg_field) {
                log_error("Option --field/-F only makes sense with list");
                return -EINVAL;
        }

        r = acquire_journal(&j, argv + 1);
        if (r < 0)
                return r;

        r = focus(j);
        if (r < 0)
                return r;

        if (arg_output) {
                f = fopen(arg_output, "we");
                if (!f)
                        return log_error_errno(errno, "Failed to open \"%s\" for writing: %m", arg_output);
        }

        print_info(f ? stdout : stderr, j, false);

        r = save_core(j, f, NULL, NULL);
        if (r < 0)
                return r;

        r = sd_journal_previous(j);
        if (r > 0 && !arg_quiet)
                log_notice("More than one entry matches, ignoring rest.");

        return 0;
}

static int run_debug(int argc, char **argv, void *userdata) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_free_ char *exe = NULL, *path = NULL, *debugger = NULL;
        bool unlink_path = false;
        const char *data, *fork_name;
        size_t len;
        pid_t pid;
        int r;

        if (!arg_debugger) {
                char *env_debugger;

                env_debugger = getenv("SYSTEMD_DEBUGGER");
                if (env_debugger)
                        arg_debugger = env_debugger;
                else
                        arg_debugger = "gdb";
        }

        debugger = strdup(arg_debugger);
        if (!debugger)
                return -ENOMEM;

        if (arg_field) {
                log_error("Option --field/-F only makes sense with list");
                return -EINVAL;
        }

        r = acquire_journal(&j, argv + 1);
        if (r < 0)
                return r;

        r = focus(j);
        if (r < 0)
                return r;

        print_info(stdout, j, false);
        fputs("\n", stdout);

        r = sd_journal_get_data(j, "COREDUMP_EXE", (const void**) &data, &len);
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve COREDUMP_EXE field: %m");

        assert(len > STRLEN("COREDUMP_EXE="));
        data += STRLEN("COREDUMP_EXE=");
        len -= STRLEN("COREDUMP_EXE=");

        exe = strndup(data, len);
        if (!exe)
                return log_oom();

        if (endswith(exe, " (deleted)")) {
                log_error("Binary already deleted.");
                return -ENOENT;
        }

        if (!path_is_absolute(exe)) {
                log_error("Binary is not an absolute path.");
                return -ENOENT;
        }

        r = save_core(j, NULL, &path, &unlink_path);
        if (r < 0)
                return r;

        /* Don't interfere with gdb and its handling of SIGINT. */
        (void) ignore_signals(SIGINT, -1);

        fork_name = strjoina("(", debugger, ")");

        r = safe_fork(fork_name, FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
        if (r < 0)
                goto finish;
        if (r == 0) {
                execlp(debugger, debugger, exe, "-c", path, NULL);
                log_open();
                log_error_errno(errno, "Failed to invoke %s: %m", debugger);
                _exit(EXIT_FAILURE);
        }

        r = wait_for_terminate_and_check(debugger, pid, WAIT_LOG_ABNORMAL);

finish:
        (void) default_signals(SIGINT, -1);

        if (unlink_path) {
                log_debug("Removed temporary file %s", path);
                (void) unlink(path);
        }

        return r;
}

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
        if (r < 0)
                return log_error_errno(r, "Failed to acquire bus: %m");

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "ListUnitsByPatterns");
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

static int coredumpctl_main(int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "list",  VERB_ANY, VERB_ANY, VERB_DEFAULT, dump_list },
                { "info",  VERB_ANY, VERB_ANY, 0,            dump_list },
                { "dump",  VERB_ANY, VERB_ANY, 0,            dump_core },
                { "debug", VERB_ANY, VERB_ANY, 0,            run_debug },
                { "gdb",   VERB_ANY, VERB_ANY, 0,            run_debug },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r, units_active;

        setlocale(LC_ALL, "");
        log_show_color(true);
        log_parse_environment();
        log_open();

        /* The journal merging logic potentially needs a lot of fds. */
        (void) rlimit_nofile_bump(HIGH_RLIMIT_NOFILE);

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        sigbus_install();

        units_active = check_units_active(); /* error is treated the same as 0 */

        r = coredumpctl_main(argc, argv);

        if (units_active > 0)
                printf("%s-- Notice: %d systemd-coredump@.service %s, output may be incomplete.%s\n",
                       ansi_highlight_red(),
                       units_active, units_active == 1 ? "unit is running" : "units are running",
                       ansi_normal());
        return r;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
