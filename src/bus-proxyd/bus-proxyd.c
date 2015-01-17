/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
  Copyright 2013 Daniel Mack
  Copyright 2014 Kay Sievers
  Copyright 2015 David Herrmann

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

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/poll.h>
#include <stddef.h>
#include <getopt.h>
#include <pthread.h>

#include "log.h"
#include "util.h"
#include "hashmap.h"
#include "socket-util.h"
#include "sd-daemon.h"
#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-util.h"
#include "build.h"
#include "strv.h"
#include "def.h"
#include "capability.h"
#include "bus-control.h"
#include "smack-util.h"
#include "set.h"
#include "bus-xml-policy.h"
#include "driver.h"
#include "proxy.h"
#include "synthesize.h"

static char *arg_address = NULL;
static char **arg_configuration = NULL;

typedef struct {
        int fd;
} ClientContext;

static ClientContext *client_context_free(ClientContext *c) {
        if (!c)
                return NULL;

        close(c->fd);
        free(c);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(ClientContext*, client_context_free);

static int client_context_new(ClientContext **out, int fd) {
        _cleanup_(client_context_freep) ClientContext *c = NULL;

        c = new0(ClientContext, 1);
        if (!c)
                return log_oom();

        c->fd = fd;

        *out = c;
        c = NULL;
        return 0;
}

static void *run_client(void *userdata) {
        _cleanup_(client_context_freep) ClientContext *c = userdata;
        _cleanup_(proxy_freep) Proxy *p = NULL;
        int r;

        r = proxy_new(&p, c->fd, c->fd, arg_address);
        if (r < 0)
                goto exit;

        r = proxy_load_policy(p, arg_configuration);
        if (r < 0)
                goto exit;

        r = proxy_hello_policy(p, getuid());
        if (r < 0)
                goto exit;

        r = proxy_run(p);

exit:
        return NULL;
}

static int loop_clients(int accept_fd) {
        pthread_attr_t attr;
        int r;

        r = pthread_attr_init(&attr);
        if (r < 0) {
                r = log_error_errno(errno, "Cannot initialize pthread attributes: %m");
                goto exit;
        }

        r = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (r < 0) {
                r = log_error_errno(errno, "Cannot mark pthread attributes as detached: %m");
                goto exit_attr;
        }

        for (;;) {
                ClientContext *c;
                pthread_t tid;
                int fd;

                fd = accept4(accept_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (fd < 0) {
                        if (errno == EAGAIN || errno == EINTR)
                                continue;

                        r = log_error_errno(errno, "accept4() failed: %m");
                        break;
                }

                r = client_context_new(&c, fd);
                if (r < 0) {
                        log_oom();
                        close(fd);
                        continue;
                }

                r = pthread_create(&tid, &attr, run_client, c);
                if (r < 0) {
                        log_error("Cannot spawn thread: %m");
                        client_context_free(c);
                        continue;
                }
        }

exit_attr:
        pthread_attr_destroy(&attr);
exit:
        return r;
}

static int help(void) {

        printf("%s [OPTIONS...]\n\n"
               "DBus proxy server.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --configuration=PATH Configuration file or directory\n"
               "     --machine=MACHINE    Connect to specified machine\n"
               "     --address=ADDRESS    Connect to the bus specified by ADDRESS\n"
               "                          (default: " DEFAULT_SYSTEM_BUS_ADDRESS ")\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_ADDRESS,
                ARG_CONFIGURATION,
                ARG_MACHINE,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "address",         required_argument, NULL, ARG_ADDRESS         },
                { "configuration",   required_argument, NULL, ARG_CONFIGURATION   },
                { "machine",         required_argument, NULL, ARG_MACHINE         },
                {},
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_ADDRESS: {
                        char *a;

                        a = strdup(optarg);
                        if (!a)
                                return log_oom();

                        free(arg_address);
                        arg_address = a;
                        break;
                }

                case ARG_CONFIGURATION:
                        r = strv_extend(&arg_configuration, optarg);
                        if (r < 0)
                                return log_oom();
                        break;

                case ARG_MACHINE: {
                        _cleanup_free_ char *e = NULL;
                        char *a;

                        e = bus_address_escape(optarg);
                        if (!e)
                                return log_oom();

#ifdef ENABLE_KDBUS
                        a = strjoin("x-machine-kernel:machine=", e, ";x-machine-unix:machine=", e, NULL);
#else
                        a = strjoin("x-machine-unix:machine=", e, NULL);
#endif
                        if (!a)
                                return log_oom();

                        free(arg_address);
                        arg_address = a;

                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (argc > optind) {
                log_error("Too many arguments");
                return -EINVAL;
        }

        if (!arg_address) {
                arg_address = strdup(DEFAULT_SYSTEM_BUS_ADDRESS);
                if (!arg_address)
                        return log_oom();
        }

        return 1;
}

int main(int argc, char *argv[]) {
        int r, accept_fd;

        log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = sd_listen_fds(0);
        if (r != 1) {
                log_error("Illegal number of file descriptors passed");
                goto finish;
        }

        accept_fd = SD_LISTEN_FDS_START;
        r = fd_nonblock(accept_fd, false);
        if (r < 0) {
                log_error_errno(r, "Cannot mark accept-fd non-blocking: %m");
                goto finish;
        }

        r = loop_clients(accept_fd);

finish:
        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Shutting down.");

        strv_free(arg_configuration);
        free(arg_address);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
