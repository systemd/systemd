/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <sys/poll.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <getopt.h>

#include "util.h"
#include "conf-parser.h"
#include "utmp-wtmp.h"

static enum {
        ACTION_LIST,
        ACTION_QUERY,
        ACTION_WATCH,
        ACTION_WALL
} arg_action = ACTION_QUERY;

static int parse_password(const char *filename) {
        char *socket_name = NULL, *message = NULL, *packet = NULL;
        uint64_t not_after = 0;
        unsigned pid = 0;
        int socket_fd = -1;

        const ConfigItem items[] = {
                { "Socket",   config_parse_string,   &socket_name, "Ask" },
                { "NotAfter", config_parse_uint64,   &not_after,   "Ask" },
                { "Message",  config_parse_string,   &message,     "Ask" },
                { "PID",      config_parse_unsigned, &pid,         "Ask" },
        };

        FILE *f;
        int r;
        usec_t n;

        assert(filename);

        if (!(f = fopen(filename, "re"))) {

                if (errno == ENOENT)
                        return 0;

                log_error("open(%s): %m", filename);
                return -errno;
        }

        if ((r = config_parse(filename, f, NULL, items, false, NULL)) < 0) {
                log_error("Failed to parse password file %s: %s", filename, strerror(-r));
                goto finish;
        }

        if (!socket_name || not_after <= 0) {
                log_error("Invalid password file %s", filename);
                r = -EBADMSG;
                goto finish;
        }

        n = now(CLOCK_MONOTONIC);
        if (n > not_after) {
                r = 0;
                goto finish;
        }

        if (arg_action == ACTION_LIST)
                printf("'%s' (PID %u)\n", message, pid);
        else if (arg_action == ACTION_WALL) {
                char *wall;

                if (asprintf(&wall,
                             "Password entry required for \'%s\' (PID %u).\r\n"
                             "Please enter password with the systemd-tty-password-agent tool!",
                             message,
                             pid) < 0) {
                        log_error("Out of memory");
                        r = -ENOMEM;
                        goto finish;
                }

                r = utmp_wall(wall);
                free(wall);
        } else {
                union {
                        struct sockaddr sa;
                        struct sockaddr_un un;
                } sa;
                char *password;

                assert(arg_action == ACTION_QUERY ||
                       arg_action == ACTION_WATCH);

                if (access(socket_name, W_OK) < 0) {

                        if (arg_action == ACTION_QUERY)
                                log_info("Not querying '%s' (PID %u), lacking privileges.", message, pid);

                        r = 0;
                        goto finish;
                }

                if ((r = ask_password_tty(message, not_after, filename, &password)) < 0) {
                        log_error("Failed to query passwords: %s", strerror(-r));
                        goto finish;
                }

                asprintf(&packet, "+%s", password);
                free(password);

                if (!packet) {
                        log_error("Out of memory");
                        r = -ENOMEM;
                        goto finish;
                }

                if ((socket_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0)) < 0) {
                        log_error("socket(): %m");
                        r = -errno;
                        goto finish;
                }

                zero(sa);
                sa.un.sun_family = AF_UNIX;
                strncpy(sa.un.sun_path, socket_name, sizeof(sa.un.sun_path));

                if (sendto(socket_fd, packet, strlen(packet), MSG_NOSIGNAL, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(socket_name)) < 0) {
                        log_error("Failed to send: %m");
                        r = -errno;
                        goto finish;
                }
        }

finish:
        fclose(f);

        if (socket_fd >= 0)
                close_nointr_nofail(socket_fd);

        free(packet);
        free(socket_name);
        free(message);

        return r;
}

static int show_passwords(void) {
        DIR *d;
        struct dirent *de;
        int r = 0;

        if (!(d = opendir("/dev/.systemd/ask-password"))) {
                if (errno == ENOENT)
                        return 0;

                log_error("opendir(): %m");
                return -errno;
        }

        while ((de = readdir(d))) {
                char *p;
                int q;

                if (de->d_type != DT_REG)
                        continue;

                if (ignore_file(de->d_name))
                        continue;

                if (!startswith(de->d_name, "ask."))
                        continue;

                if (!(p = strappend("/dev/.systemd/ask-password/", de->d_name))) {
                        log_error("Out of memory");
                        r = -ENOMEM;
                        goto finish;
                }

                if ((q = parse_password(p)) < 0)
                        r = q;

                free(p);
        }

finish:
        if (d)
                closedir(d);

        return r;
}

static int watch_passwords(void) {
        int notify;
        struct pollfd pollfd;
        int r;

        mkdir_p("/dev/.systemd/ask-password", 0755);

        if ((notify = inotify_init1(IN_CLOEXEC)) < 0) {
                r = -errno;
                goto finish;
        }

        if (inotify_add_watch(notify, "/dev/.systemd/ask-password", IN_CLOSE_WRITE|IN_MOVED_TO) < 0) {
                r = -errno;
                goto finish;
        }

        zero(pollfd);
        pollfd.fd = notify;
        pollfd.events = POLLIN;

        for (;;) {
                if ((r = show_passwords()) < 0)
                        break;

                if (poll(&pollfd, 1, -1) < 0) {

                        if (errno == EINTR)
                                continue;

                        r = -errno;
                        goto finish;
                }

                if (pollfd.revents != 0)
                        flush_fd(notify);
        }

        r = 0;

finish:
        if (notify >= 0)
                close_nointr_nofail(notify);

        return r;
}

static int help(void) {

        printf("%s [OPTIONS...]\n\n"
               "Process system password requests.\n\n"
               "  -h --help   Show this help\n"
               "     --list   Show pending password requests\n"
               "     --query  Process pending password requests\n"
               "     --watch  Continously process password requests\n"
               "     --wall   Continously forward password requests to wall\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_LIST = 0x100,
                ARG_QUERY,
                ARG_WATCH,
                ARG_WALL,
        };

        static const struct option options[] = {
                { "help",  no_argument, NULL, 'h'       },
                { "list",  no_argument, NULL, ARG_LIST  },
                { "query", no_argument, NULL, ARG_QUERY },
                { "watch", no_argument, NULL, ARG_WATCH },
                { "wall",  no_argument, NULL, ARG_WALL  },
                { NULL,    0,           NULL, 0         }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_LIST:
                        arg_action = ACTION_LIST;
                        break;

                case ARG_QUERY:
                        arg_action = ACTION_QUERY;
                        break;

                case ARG_WATCH:
                        arg_action = ACTION_WATCH;
                        break;

                case ARG_WALL:
                        arg_action = ACTION_WALL;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        if (optind != argc) {
                help();
                return -EINVAL;
        }

        return 1;
}

int main(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        if ((r = parse_argv(argc, argv)) <= 0)
                goto finish;

        if (arg_action == ACTION_WATCH ||
            arg_action == ACTION_WALL)
                r = watch_passwords();
        else
                r = show_passwords();

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
