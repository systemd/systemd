/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include "systemd/sd-journal.h"

#include "util.h"
#include "build.h"

static char *arg_identifier = NULL;
static int arg_priority = LOG_INFO;
static bool arg_level_prefix = true;

static void help(void) {
        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Execute process with stdout/stderr connected to the journal.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "  -t --identifier=STRING  Set syslog identifier\n"
               "  -p --priority=PRIORITY  Set priority value (0..7)\n"
               "     --level-prefix=BOOL  Control whether level prefix shall be parsed\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_LEVEL_PREFIX
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "identifier",   required_argument, NULL, 't'              },
                { "priority",     required_argument, NULL, 'p'              },
                { "level-prefix", required_argument, NULL, ARG_LEVEL_PREFIX },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+ht:p:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case 't':
                        free(arg_identifier);
                        if (isempty(optarg))
                                arg_identifier = NULL;
                        else {
                                arg_identifier = strdup(optarg);
                                if (!arg_identifier)
                                        return log_oom();
                        }
                        break;

                case 'p':
                        arg_priority = log_level_from_string(optarg);
                        if (arg_priority < 0) {
                                log_error("Failed to parse priority value.");
                                return arg_priority;
                        }
                        break;

                case ARG_LEVEL_PREFIX: {
                        int k;

                        k = parse_boolean(optarg);
                        if (k < 0) {
                                log_error("Failed to parse level prefix value.");
                                return k;
                        }
                        arg_level_prefix = k;
                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

int main(int argc, char *argv[]) {
        int r, fd = -1, saved_stderr = -1;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        fd = sd_journal_stream_fd(arg_identifier, arg_priority, arg_level_prefix);
        if (fd < 0) {
                log_error_errno(fd, "Failed to create stream fd: %m");
                r = fd;
                goto finish;
        }

        saved_stderr = fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 3);

        if (dup3(fd, STDOUT_FILENO, 0) < 0 ||
            dup3(fd, STDERR_FILENO, 0) < 0) {
                log_error_errno(errno, "Failed to duplicate fd: %m");
                r = -errno;
                goto finish;
        }

        if (fd >= 3)
                safe_close(fd);

        fd = -1;

        if (argc <= optind)
                execl("/bin/cat", "/bin/cat", NULL);
        else
                execvp(argv[optind], argv + optind);

        r = -errno;

        /* Let's try to restore a working stderr, so we can print the error message */
        if (saved_stderr >= 0)
                dup3(saved_stderr, STDERR_FILENO, 0);

        log_error_errno(r, "Failed to execute process: %m");

finish:
        safe_close(fd);
        safe_close(saved_stderr);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
