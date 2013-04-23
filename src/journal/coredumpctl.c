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

static enum {
        ACTION_NONE,
        ACTION_LIST,
        ACTION_DUMP,
        ACTION_GDB,
} arg_action = ACTION_LIST;

static FILE* output = NULL;
static char* field = NULL;

static int arg_no_pager = false;
static int arg_no_legend = false;

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
        printf("%s [OPTIONS...] [MATCHES...]\n\n"
               "List or retrieve coredumps from the journal.\n\n"
               "Flags:\n"
               "  -o --output=FILE  Write output to FILE\n"
               "     --no-pager     Do not pipe output into a pager\n"

               "Commands:\n"
               "  -h --help         Show this help\n"
               "  --version         Print version string\n"
               "  -F --field=FIELD  List all values a certain field takes\n"
               "  gdb               Start gdb for the first matching coredump\n"
               "  list              List available coredumps\n"
               "  dump PID          Print coredump to stdout\n"
               "  dump PATH         Print coredump to stdout\n"
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
        r = set_consume(set, pattern);
        if (r < 0) {
                log_error("Failed to add pattern '%s': %s",
                          pattern, strerror(-r));
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
                { NULL,           0,                 NULL, 0             }
        };

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ho:F:", options, NULL)) >= 0)
                switch(c) {
                case 'h':
                        help();
                        arg_action = ACTION_NONE;
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        arg_action = ACTION_NONE;
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
                        if (field) {
                                log_error("cannot use --field/-F more than once");
                                return -EINVAL;
                        }

                        field = optarg;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }

        if (optind < argc) {
                const char *cmd = argv[optind++];
                if(streq(cmd, "list"))
                        arg_action = ACTION_LIST;
                else if (streq(cmd, "dump"))
                        arg_action = ACTION_DUMP;
                else if (streq(cmd, "gdb"))
                        arg_action = ACTION_GDB;
                else {
                        log_error("Unknown action '%s'", cmd);
                        return -EINVAL;
                }
        }

        if (field && arg_action != ACTION_LIST) {
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
                    const char **var) {

        size_t ident;

        ident = strlen(name) + 1; /* name + "=" */

        if (len < ident)
                return 0;

        if (memcmp(data, name, ident - 1) != 0)
                return 0;

        if (((const char*) data)[ident - 1] != '=')
                return 0;

        *var = strndup((const char*)data + ident, len - ident);
        if (!*var)
                return log_oom();

        return 0;
}

static void print_field(FILE* file, sd_journal *j) {
        _cleanup_free_ const char *value = NULL;
        const void *d;
        size_t l;

        assert(field);

        SD_JOURNAL_FOREACH_DATA(j, d, l)
                retrieve(d, l, field, &value);
        if (value)
                fprintf(file, "%s\n", value);
}

static int print_entry(FILE* file, sd_journal *j, int had_legend) {
        _cleanup_free_ const char
                *pid = NULL, *uid = NULL, *gid = NULL,
                *sgnl = NULL, *exe = NULL;
        const void *d;
        size_t l;
        usec_t t;
        char buf[FORMAT_TIMESTAMP_MAX];
        int r;

        SD_JOURNAL_FOREACH_DATA(j, d, l) {
                retrieve(d, l, "COREDUMP_PID", &pid);
                retrieve(d, l, "COREDUMP_PID", &pid);
                retrieve(d, l, "COREDUMP_UID", &uid);
                retrieve(d, l, "COREDUMP_GID", &gid);
                retrieve(d, l, "COREDUMP_SIGNAL", &sgnl);
                retrieve(d, l, "COREDUMP_EXE", &exe);
                if (!exe)
                        retrieve(d, l, "COREDUMP_COMM", &exe);
                if (!exe)
                        retrieve(d, l, "COREDUMP_CMDLINE", &exe);
        }

        if (!pid && !uid && !gid && !sgnl && !exe) {
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
                6, pid,
                5, uid,
                5, gid,
                3, sgnl,
                exe);

        return 0;
}

static int dump_list(sd_journal *j) {
        int found = 0;

        assert(j);

        /* The coredumps are likely to compressed, and for just
         * listing them we don#t need to decompress them, so let's
         * pick a fairly low data threshold here */
        sd_journal_set_data_threshold(j, 4096);

        SD_JOURNAL_FOREACH(j) {
                if (field)
                        print_field(stdout, j);
                else
                        print_entry(stdout, j, found++);
        }

        if (!field && !found) {
                log_notice("No coredumps found");
                return -ESRCH;
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
                log_error("No match found");
                return -ESRCH;
        }
        return r;
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

        print_entry(output ? stdout : stderr, j, false);

        if (on_tty() && !output) {
                log_error("Refusing to dump core to tty");
                return -ENOTTY;
        }

        r = sd_journal_get_data(j, "COREDUMP", (const void**) &data, &len);
        if (r < 0) {
                log_error("Failed to retrieve COREDUMP field: %s", strerror(-r));
                return r;
        }

        assert(len >= 9);
        data = (const uint8_t*) data + 9;
        len -= 9;

        ret = fwrite(data, len, 1, output ? output : stdout);
        if (ret != 1) {
                log_error("dumping coredump: %m (%zu)", ret);
                return -errno;
        }

        r = sd_journal_previous(j);
        if (r >= 0)
                log_warning("More than one entry matches, ignoring rest.\n");

        return 0;
}

static int run_gdb(sd_journal *j) {
        char path[] = "/var/tmp/coredump-XXXXXX";
        const void *data;
        size_t len;
        ssize_t sz;
        pid_t pid;
        _cleanup_free_ char *exe = NULL;
        int r;
        _cleanup_close_ int fd = -1;
        siginfo_t st;

        assert(j);

        sd_journal_set_data_threshold(j, 0);

        r = focus(j);
        if (r < 0)
                return r;

        print_entry(stdout, j, false);

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

        r = sd_journal_get_data(j, "COREDUMP", (const void**) &data, &len);
        if (r < 0) {
                log_error("Failed to retrieve COREDUMP field: %s", strerror(-r));
                return r;
        }

        assert(len >= 9);
        data = (const uint8_t*) data + 9;
        len -= 9;

        fd = mkostemp(path, O_WRONLY);
        if (fd < 0) {
                log_error("Failed to create temporary file: %m");
                return -errno;
        }

        sz = write(fd, data, len);
        if (sz < 0) {
                log_error("Failed to write temporary file: %s", strerror(errno));
                r = -errno;
                goto finish;
        }
        if (sz != (ssize_t) len) {
                log_error("Short write to temporary file.");
                r = -EIO;
                goto finish;
        }

        close_nointr_nofail(fd);
        fd = -1;

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
        unlink(path);
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

        switch(arg_action) {

        case ACTION_LIST:
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
