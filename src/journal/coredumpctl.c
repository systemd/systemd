/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>

#include <systemd/sd-journal.h>

#include "build.h"
#include "set.h"
#include "util.h"
#include "log.h"
#include "path-util.h"
#include "pager.h"
#include "macro.h"
#include "journal-internal.h"
#include "copy.h"

static enum {
        ACTION_NONE,
        ACTION_INFO,
        ACTION_LIST,
        ACTION_DUMP,
        ACTION_GDB,
} arg_action = ACTION_LIST;
static const char* arg_field = NULL;
static int arg_no_pager = false;
static int arg_no_legend = false;
static int arg_one = false;

static FILE* output = NULL;

static Set *new_matches(void) {
        Set *set;
        char *tmp;
        int r;

        set = set_new(trivial_hash_func, trivial_compare_func);
        if (!set) {
                log_oom();
                return NULL;
        }

        tmp = strdup("MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1");
        if (!tmp) {
                log_oom();
                set_free(set);
                return NULL;
        }

        r = set_consume(set, tmp);
        if (r < 0) {
                log_error("failed to add to set: %s", strerror(-r));
                set_free(set);
                return NULL;
        }

        return set;
}

static int help(void) {

        printf("%s [OPTIONS...]\n\n"
               "List or retrieve coredumps from the journal.\n\n"
               "Flags:\n"
               "  -o --output=FILE   Write output to FILE\n"
               "     --no-pager      Do not pipe output into a pager\n"
               "     --no-legend     Do not print the column headers.\n\n"

               "Commands:\n"
               "  -h --help          Show this help\n"
               "  --version          Print version string\n"
               "  -F --field=FIELD   List all values a certain field takes\n"
               "  list [MATCHES...]  List available coredumps\n"
               "  info [MATCHES...]  Show detailed information about one or more coredumps\n"
               "  dump [MATCHES...]  Print first matching coredump to stdout\n"
               "  gdb [MATCHES...]   Start gdb for the first matching coredump\n"
               , program_invocation_short_name);

        return 0;
}

static int add_match(Set *set, const char *match) {
        int r = -ENOMEM;
        unsigned pid;
        const char* prefix;
        char *pattern = NULL;
        _cleanup_free_ char *p = NULL;

        if (strchr(match, '='))
                prefix = "";
        else if (strchr(match, '/')) {
                p = path_make_absolute_cwd(match);
                if (!p)
                        goto fail;

                match = p;
                prefix = "COREDUMP_EXE=";
        }
        else if (safe_atou(match, &pid) == 0)
                prefix = "COREDUMP_PID=";
        else
                prefix = "COREDUMP_COMM=";

        pattern = strjoin(prefix, match, NULL);
        if (!pattern)
                goto fail;

        log_debug("Adding pattern: %s", pattern);
        r = set_put(set, pattern);
        if (r < 0) {
                log_error("Failed to add pattern '%s': %s",
                          pattern, strerror(-r));
                free(pattern);
                goto fail;
        }

        return 0;
fail:
        log_error("Failed to add match: %s", strerror(-r));
        return r;
}

static int parse_argv(int argc, char *argv[], Set *matches) {
        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
        };

        int r, c;

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'           },
                { "version" ,     no_argument,       NULL, ARG_VERSION   },
                { "no-pager",     no_argument,       NULL, ARG_NO_PAGER  },
                { "no-legend",    no_argument,       NULL, ARG_NO_LEGEND },
                { "output",       required_argument, NULL, 'o'           },
                { "field",        required_argument, NULL, 'F'           },
                {}
        };

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ho:F:1", options, NULL)) >= 0)
                switch(c) {

                case 'h':
                        arg_action = ACTION_NONE;
                        return help();

                case ARG_VERSION:
                        arg_action = ACTION_NONE;
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case ARG_NO_LEGEND:
                        arg_no_legend = true;
                        break;

                case 'o':
                        if (output) {
                                log_error("cannot set output more than once");
                                return -EINVAL;
                        }

                        output = fopen(optarg, "we");
                        if (!output) {
                                log_error("writing to '%s': %m", optarg);
                                return -errno;
                        }

                        break;

                case 'F':
                        if (arg_field) {
                                log_error("cannot use --field/-F more than once");
                                return -EINVAL;
                        }
                        arg_field = optarg;
                        break;

                case '1':
                        arg_one = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (optind < argc) {
                const char *cmd = argv[optind++];
                if (streq(cmd, "list"))
                        arg_action = ACTION_LIST;
                else if (streq(cmd, "dump"))
                        arg_action = ACTION_DUMP;
                else if (streq(cmd, "gdb"))
                        arg_action = ACTION_GDB;
                else if (streq(cmd, "info"))
                        arg_action = ACTION_INFO;
                else {
                        log_error("Unknown action '%s'", cmd);
                        return -EINVAL;
                }
        }

        if (arg_field && arg_action != ACTION_LIST) {
                log_error("Option --field/-F only makes sense with list");
                return -EINVAL;
        }

        while (optind < argc) {
                r = add_match(matches, argv[optind]);
                if (r != 0)
                        return r;
                optind++;
        }

        return 0;
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

        free(*var);
        *var = v;

        return 0;
}

#define filename_escape(s) xescape((s), "./")

static int make_coredump_path(sd_journal *j, char **ret) {
        _cleanup_free_ char
                *pid = NULL, *boot_id = NULL, *tstamp = NULL, *comm = NULL,
                *p = NULL, *b = NULL, *t = NULL, *c = NULL;
        const void *d;
        size_t l;
        char *fn;

        assert(j);
        assert(ret);

        SD_JOURNAL_FOREACH_DATA(j, d, l) {
                retrieve(d, l, "COREDUMP_COMM", &comm);
                retrieve(d, l, "COREDUMP_PID", &pid);
                retrieve(d, l, "COREDUMP_TIMESTAMP", &tstamp);
                retrieve(d, l, "_BOOT_ID", &boot_id);
        }

        if (!pid || !comm || !tstamp || !boot_id) {
                log_error("Failed to retrieve necessary fields to find coredump on disk.");
                return -ENOENT;
        }

        p = filename_escape(pid);
        if (!p)
                return log_oom();

        t = filename_escape(tstamp);
        if (!t)
                return log_oom();

        c = filename_escape(comm);
        if (!t)
                return log_oom();

        b = filename_escape(boot_id);
        if (!b)
                return log_oom();

        fn = strjoin("/var/lib/systemd/coredump/core.", c, ".", b, ".", p, ".", t, NULL);
        if (!fn)
                return log_oom();

        *ret = fn;
        return 0;
}

static void print_field(FILE* file, sd_journal *j) {
        _cleanup_free_ char *value = NULL;
        const void *d;
        size_t l;

        assert(file);
        assert(j);

        assert(arg_field);

        SD_JOURNAL_FOREACH_DATA(j, d, l)
                retrieve(d, l, arg_field, &value);

        if (value)
                fprintf(file, "%s\n", value);
}

static int print_list(FILE* file, sd_journal *j, int had_legend) {
        _cleanup_free_ char
                *pid = NULL, *uid = NULL, *gid = NULL,
                *sgnl = NULL, *exe = NULL, *comm = NULL, *cmdline = NULL;
        const void *d;
        size_t l;
        usec_t t;
        char buf[FORMAT_TIMESTAMP_MAX];
        int r;

        assert(file);
        assert(j);

        SD_JOURNAL_FOREACH_DATA(j, d, l) {
                retrieve(d, l, "COREDUMP_PID", &pid);
                retrieve(d, l, "COREDUMP_UID", &uid);
                retrieve(d, l, "COREDUMP_GID", &gid);
                retrieve(d, l, "COREDUMP_SIGNAL", &sgnl);
                retrieve(d, l, "COREDUMP_EXE", &exe);
                retrieve(d, l, "COREDUMP_COMM", &comm);
                retrieve(d, l, "COREDUMP_CMDLINE", &cmdline);
        }

        if (!pid && !uid && !gid && !sgnl && !exe && !comm && !cmdline) {
                log_warning("Empty coredump log entry");
                return -EINVAL;
        }

        r = sd_journal_get_realtime_usec(j, &t);
        if (r < 0) {
                log_error("Failed to get realtime timestamp: %s", strerror(-r));
                return r;
        }

        format_timestamp(buf, sizeof(buf), t);

        if (!had_legend && !arg_no_legend)
                fprintf(file, "%-*s %*s %*s %*s %*s %s\n",
                        FORMAT_TIMESTAMP_MAX-1, "TIME",
                        6, "PID",
                        5, "UID",
                        5, "GID",
                        3, "SIG",
                           "EXE");

        fprintf(file, "%*s %*s %*s %*s %*s %s\n",
                FORMAT_TIMESTAMP_MAX-1, buf,
                6, strna(pid),
                5, strna(uid),
                5, strna(gid),
                3, strna(sgnl),
                strna(exe ?: (comm ?: cmdline)));

        return 0;
}

static int print_info(FILE *file, sd_journal *j, bool need_space) {
        _cleanup_free_ char
                *pid = NULL, *uid = NULL, *gid = NULL,
                *sgnl = NULL, *exe = NULL, *comm = NULL, *cmdline = NULL,
                *unit = NULL, *user_unit = NULL, *session = NULL,
                *boot_id = NULL, *machine_id = NULL, *hostname = NULL,
                *coredump = NULL, *slice = NULL, *cgroup = NULL,
                *owner_uid = NULL, *message = NULL;
        const void *d;
        size_t l;

        assert(file);
        assert(j);

        SD_JOURNAL_FOREACH_DATA(j, d, l) {
                retrieve(d, l, "COREDUMP_PID", &pid);
                retrieve(d, l, "COREDUMP_UID", &uid);
                retrieve(d, l, "COREDUMP_GID", &gid);
                retrieve(d, l, "COREDUMP_SIGNAL", &sgnl);
                retrieve(d, l, "COREDUMP_EXE", &exe);
                retrieve(d, l, "COREDUMP_COMM", &comm);
                retrieve(d, l, "COREDUMP_CMDLINE", &cmdline);
                retrieve(d, l, "COREDUMP_UNIT", &unit);
                retrieve(d, l, "COREDUMP_USER_UNIT", &user_unit);
                retrieve(d, l, "COREDUMP_SESSION", &session);
                retrieve(d, l, "COREDUMP_OWNER_UID", &owner_uid);
                retrieve(d, l, "COREDUMP_SLICE", &slice);
                retrieve(d, l, "COREDUMP_CGROUP", &cgroup);
                retrieve(d, l, "_BOOT_ID", &boot_id);
                retrieve(d, l, "_MACHINE_ID", &machine_id);
                retrieve(d, l, "_HOSTNAME", &hostname);
                retrieve(d, l, "MESSAGE", &message);
        }

        if (need_space)
                fputs("\n", file);

        fprintf(file,
                "           PID: %s%s%s\n",
                ansi_highlight(), strna(pid), ansi_highlight_off());

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

                if (safe_atoi(sgnl, &sig) >= 0)
                        fprintf(file, "        Signal: %s (%s)\n", sgnl, signal_to_string(sig));
                else
                        fprintf(file, "        Signal: %s\n", sgnl);
        }

        if (exe)
                fprintf(file, "    Executable: %s%s%s\n", ansi_highlight(), exe, ansi_highlight_off());
        if (comm)
                fprintf(file, "          Comm: %s\n", comm);
        if (cmdline)
                fprintf(file, "  Command Line: %s\n", cmdline);
        if (cgroup)
                fprintf(file, " Control Group: %s\n", cgroup);
        if (unit)
                fprintf(file, "          Unit: %s\n", unit);
        if (user_unit)
                fprintf(file, "     User Unit: %s\n", unit);
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

        if (make_coredump_path(j, &coredump) >= 0)
                if (access(coredump, F_OK) >= 0)
                        fprintf(file, "      Coredump: %s\n", coredump);

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
        if (r < 0) {
                log_error("Failed to search journal: %s", strerror(-r));
                return r;
        }
        if (r == 0) {
                log_error("No match found.");
                return -ESRCH;
        }
        return r;
}

static void print_entry(sd_journal *j, unsigned n_found) {
        assert(j);

        if (arg_action == ACTION_INFO)
                print_info(stdout, j, n_found);
        else if (arg_field)
                print_field(stdout, j);
        else
                print_list(stdout, j, n_found);
}

static int dump_list(sd_journal *j) {
        unsigned n_found = 0;
        int r;

        assert(j);

        /* The coredumps are likely to compressed, and for just
         * listing them we don't need to decompress them, so let's
         * pick a fairly low data threshold here */
        sd_journal_set_data_threshold(j, 4096);

        if (arg_one) {
                r = focus(j);
                if (r < 0)
                        return r;

                print_entry(j, 0);
        } else {
                SD_JOURNAL_FOREACH(j)
                        print_entry(j, n_found++);

                if (!arg_field && n_found <= 0) {
                        log_notice("No coredumps found.");
                        return -ESRCH;
                }
        }

        return 0;
}

static int dump_core(sd_journal* j) {
        const void *data;
        size_t len, ret;
        int r;

        assert(j);

        /* We want full data, nothing truncated. */
        sd_journal_set_data_threshold(j, 0);

        r = focus(j);
        if (r < 0)
                return r;

        print_info(output ? stdout : stderr, j, false);

        if (on_tty() && !output) {
                log_error("Refusing to dump core to tty.");
                return -ENOTTY;
        }

        r = sd_journal_get_data(j, "COREDUMP", (const void**) &data, &len);
        if (r == ENOENT) {
                _cleanup_free_ char *fn = NULL;
                _cleanup_close_ int fd = -1;

                r = make_coredump_path(j, &fn);
                if (r < 0)
                        return r;

                fd = open(fn, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0) {
                        if (errno == ENOENT)
                                log_error("Coredump neither in journal file nor stored externally on disk.");
                        else
                                log_error("Failed to open coredump file: %s", strerror(-r));

                        return -errno;
                }

                r = copy_bytes(fd, output ? fileno(output) : STDOUT_FILENO);
                if (r < 0) {
                        log_error("Failed to stream coredump: %s", strerror(-r));
                        return r;
                }

        } else if (r < 0) {
                log_error("Failed to retrieve COREDUMP field: %s", strerror(-r));
                return r;

        } else {
                assert(len >= 9);
                data = (const uint8_t*) data + 9;
                len -= 9;

                ret = fwrite(data, len, 1, output ?: stdout);
                if (ret != 1) {
                        log_error("Dumping coredump failed: %m (%zu)", ret);
                        return -errno;
                }
        }

        r = sd_journal_previous(j);
        if (r >= 0)
                log_warning("More than one entry matches, ignoring rest.");

        return 0;
}

static int run_gdb(sd_journal *j) {

        _cleanup_free_ char *exe = NULL, *coredump = NULL;
        char temp[] = "/var/tmp/coredump-XXXXXX";
        bool unlink_temp = false;
        const char *path;
        const void *data;
        siginfo_t st;
        size_t len;
        pid_t pid;
        int r;

        assert(j);

        sd_journal_set_data_threshold(j, 0);

        r = focus(j);
        if (r < 0)
                return r;

        print_info(stdout, j, false);
        fputs("\n", stdout);

        r = sd_journal_get_data(j, "COREDUMP_EXE", (const void**) &data, &len);
        if (r < 0) {
                log_error("Failed to retrieve COREDUMP_EXE field: %s", strerror(-r));
                return r;
        }

        assert(len >= 13);
        data = (const uint8_t*) data + 13;
        len -= 13;

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

        r = sd_journal_get_data(j, "COREDUMP", (const void**) &data, &len);
        if (r == -ENOENT) {

                r = make_coredump_path(j, &coredump);
                if (r < 0)
                        return r;

                if (access(coredump, R_OK) < 0) {
                        if (errno == ENOENT)
                                log_error("Coredump neither in journal file nor stored externally on disk.");
                        else
                                log_error("Failed to access coredump file: %m");

                        return -errno;
                }

                path = coredump;

        } else if (r < 0) {
                log_error("Failed to retrieve COREDUMP field: %s", strerror(-r));
                return r;

        } else {
                _cleanup_close_ int fd = -1;
                ssize_t sz;

                assert(len >= 9);
                data = (const uint8_t*) data + 9;
                len -= 9;

                fd = mkostemp_safe(temp, O_WRONLY|O_CLOEXEC);
                if (fd < 0) {
                        log_error("Failed to create temporary file: %m");
                        return -errno;
                }

                unlink_temp = true;

                sz = write(fd, data, len);
                if (sz < 0) {
                        log_error("Failed to write temporary file: %m");
                        r = -errno;
                        goto finish;
                }
                if (sz != (ssize_t) len) {
                        log_error("Short write to temporary file.");
                        r = -EIO;
                        goto finish;
                }

                path = temp;
        }

        pid = fork();
        if (pid < 0) {
                log_error("Failed to fork(): %m");
                r = -errno;
                goto finish;
        }
        if (pid == 0) {
                execlp("gdb", "gdb", exe, path, NULL);

                log_error("Failed to invoke gdb: %m");
                _exit(1);
        }

        r = wait_for_terminate(pid, &st);
        if (r < 0) {
                log_error("Failed to wait for gdb: %m");
                goto finish;
        }

        r = st.si_code == CLD_EXITED ? st.si_status : 255;

finish:
        if (unlink_temp)
                unlink(temp);

        return r;
}

int main(int argc, char *argv[]) {
        _cleanup_journal_close_ sd_journal*j = NULL;
        const char* match;
        Iterator it;
        int r = 0;
        _cleanup_set_free_free_ Set *matches = NULL;

        setlocale(LC_ALL, "");
        log_parse_environment();
        log_open();

        matches = new_matches();
        if (!matches) {
                r = -ENOMEM;
                goto end;
        }

        r = parse_argv(argc, argv, matches);
        if (r < 0)
                goto end;

        if (arg_action == ACTION_NONE)
                goto end;

        r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
        if (r < 0) {
                log_error("Failed to open journal: %s", strerror(-r));
                goto end;
        }

        SET_FOREACH(match, matches, it) {
                r = sd_journal_add_match(j, match, strlen(match));
                if (r != 0) {
                        log_error("Failed to add match '%s': %s",
                                  match, strerror(-r));
                        goto end;
                }
        }

        if (_unlikely_(log_get_max_level() >= LOG_PRI(LOG_DEBUG))) {
                _cleanup_free_ char *filter;

                filter = journal_make_match_string(j);
                log_debug("Journal filter: %s", filter);
        }

        switch(arg_action) {

        case ACTION_LIST:
        case ACTION_INFO:
                if (!arg_no_pager)
                        pager_open(false);

                r = dump_list(j);
                break;

        case ACTION_DUMP:
                r = dump_core(j);
                break;

        case  ACTION_GDB:
                r = run_gdb(j);
                break;

        default:
                assert_not_reached("Shouldn't be here");
        }

end:
        pager_close();

        if (output)
                fclose(output);

        return r >= 0 ? r : EXIT_FAILURE;
}
