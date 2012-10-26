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

#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include <systemd/sd-journal.h>

#include "build.h"
#include "set.h"
#include "util.h"
#include "log.h"
#include "path-util.h"
#include "pager.h"

static enum {
        ACTION_NONE,
        ACTION_LIST,
        ACTION_DUMP,
} arg_action = ACTION_LIST;

static Set *matches = NULL;
static FILE* output = NULL;

static int arg_no_pager = false;

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
                set_clear_free(set);
                return NULL;
        }

        r = set_put(set, tmp);
        if (r < 0) {
                log_error("failed to add to set: %s", strerror(-r));
                free(tmp);
                set_clear_free(set);
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
        char _cleanup_free_ *p = NULL;

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

        r = set_put(set, pattern);
        if (r < 0) {
                log_error("failed to add pattern '%s': %s",
                          pattern, strerror(-r));
                goto fail;
        }
        log_debug("Added pattern: %s", pattern);

        return 0;
fail:
        free(pattern);
        log_error("failed to add match: %s", strerror(-r));
        return r;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
        };

        int r, c;

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version" ,     no_argument,       NULL, ARG_VERSION      },
                { "no-pager",     no_argument,       NULL, ARG_NO_PAGER     },
                { "output",       required_argument, NULL, 'o'              },
        };

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ho:", options, NULL)) >= 0)
                switch(c) {
                case 'h':
                        help();
                        arg_action = ACTION_NONE;
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(DISTRIBUTION);
                        puts(SYSTEMD_FEATURES);
                        arg_action = ACTION_NONE;
                        return 0;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
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
                else {
                        log_error("Unknown action '%s'", cmd);
                        return -EINVAL;
                }
        }

        while (optind < argc) {
                r = add_match(matches, argv[optind]);
                if (r != 0)
                        return r;
                optind++;
        }

        return 0;
}

static int retrieve(sd_journal *j, const char *name, const char **var) {
        const void *data;
        size_t len, field;
        int r;

        r = sd_journal_get_data(j, name, &data, &len);
        if (r < 0) {
                log_warning("Failed to retrieve %s", name);
                return r;
        }

        field = strlen(name) + 1; // name + "="
        assert(len >= field);

        *var = strndup((const char*)data + field, len - field);
        if (!var)
                return log_oom();

        return 0;
}

static void print_entry(FILE* file, sd_journal *j, int had_header) {
        const char _cleanup_free_
                *pid = NULL, *uid = NULL, *gid = NULL,
                *sgnl = NULL, *exe = NULL;

        retrieve(j, "COREDUMP_PID", &pid);
        retrieve(j, "COREDUMP_UID", &uid);
        retrieve(j, "COREDUMP_GID", &gid);
        retrieve(j, "COREDUMP_SIGNAL", &sgnl);
        retrieve(j, "COREDUMP_EXE", &exe);
        if (!exe)
                retrieve(j, "COREDUMP_COMM", &exe);
        if (!exe)
                retrieve(j, "COREDUMP_CMDLINE", &exe);

        if (!pid && !uid && !gid && !sgnl && !exe) {
                log_warning("empty coredump log entry");
                return;
        }

        if (!had_header)
                fprintf(file, "%*s %*s %*s %*s %s\n",
                        6, "PID",
                        5, "UID",
                        5, "GID",
                        3, "sig",
                        "exe");

        fprintf(file, "%*s %*s %*s %*s %s\n",
                6, pid,
                5, uid,
                5, gid,
                3, sgnl,
                exe);
}

static int dump_list(sd_journal *j) {
        int found = 0;

        assert(j);

        SD_JOURNAL_FOREACH(j)
                print_entry(stdout, j, found++);

        if (!found) {
                log_error("no coredumps found");
                return -ESRCH;
        }

        return 0;
}

static int dump_core(sd_journal* j) {
        const char *data;
        size_t len, ret;
        int r;

        assert(j);

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

        r = sd_journal_get_data(j, "COREDUMP", (const void**) &data, &len);
        if (r != 0) {
                log_error("retrieve COREDUMP field: %s", strerror(-r));
                return r;
        }

        print_entry(output ? stdout : stderr, j, false);

        if (on_tty() && !output) {
                log_error("Refusing to dump core to tty");
                return -ENOTTY;
        }

        assert(len >= 9);

        ret = fwrite(data+9, len-9, 1, output ? output : stdout);
        if (ret != 1) {
                log_error("dumping coredump: %m (%zu)", ret);
                return -errno;
        }

        r = sd_journal_previous(j);
        if (r >= 0)
                log_warning("More than one entry matches, ignoring rest.\n");

        return 0;
}

int main(int argc, char *argv[]) {
        sd_journal *j = NULL;
        const char* match;
        Iterator it;
        int r = 0;

        log_parse_environment();
        log_open();

        matches = new_matches();
        if (!matches)
                goto end;

        if (parse_argv(argc, argv))
                goto end;

        if (arg_action == ACTION_NONE)
                goto end;

        r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
        if (r < 0) {
                log_error("Failed to open journal: %s", strerror(-r));
                goto end;
        }

        SET_FOREACH(match, matches, it) {
                log_info("Matching: %s", match);

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
                        pager_open();

                r = dump_list(j);
                break;
        case ACTION_DUMP:
                r = dump_core(j);
                break;
        case ACTION_NONE:
                assert_not_reached("Shouldn't be here");
        }

end:
        if (j)
                sd_journal_close(j);

        set_free_free(matches);

        pager_close();

        if (output)
                fclose(output);

        return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
