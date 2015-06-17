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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <stddef.h>
#include <getopt.h>
#include <pthread.h>

#include "log.h"
#include "util.h"
#include "sd-daemon.h"
#include "bus-internal.h"
#include "build.h"
#include "strv.h"
#include "def.h"
#include "capability.h"
#include "bus-xml-policy.h"
#include "proxy.h"
#include "formats-util.h"

static char *arg_address = NULL;
static char **arg_configuration = NULL;

typedef struct {
        int fd;
        SharedPolicy *policy;
        uid_t bus_uid;
} ClientContext;

static ClientContext *client_context_free(ClientContext *c) {
        if (!c)
                return NULL;

        safe_close(c->fd);
        free(c);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(ClientContext*, client_context_free);

static int client_context_new(ClientContext **out) {
        _cleanup_(client_context_freep) ClientContext *c = NULL;

        c = new0(ClientContext, 1);
        if (!c)
                return -ENOMEM;

        c->fd = -1;

        *out = c;
        c = NULL;
        return 0;
}

static void *run_client(void *userdata) {
        _cleanup_(client_context_freep) ClientContext *c = userdata;
        _cleanup_(proxy_freep) Proxy *p = NULL;
        char comm[16];
        int r;

        r = proxy_new(&p, c->fd, c->fd, arg_address);
        if (r < 0)
                goto exit;

        c->fd = -1;

        /* set comm to "p$PIDu$UID" and suffix with '*' if truncated */
        r = snprintf(comm, sizeof(comm), "p" PID_FMT "u" UID_FMT, p->local_creds.pid, p->local_creds.uid);
        if (r >= (ssize_t)sizeof(comm))
                comm[sizeof(comm) - 2] = '*';
        (void) prctl(PR_SET_NAME, comm);

        r = proxy_set_policy(p, c->policy, arg_configuration);
        if (r < 0)
                goto exit;

        r = proxy_hello_policy(p, c->bus_uid);
        if (r < 0)
                goto exit;

        r = proxy_run(p);

exit:
        return NULL;
}

static int loop_clients(int accept_fd, uid_t bus_uid) {
        _cleanup_(shared_policy_freep) SharedPolicy *sp = NULL;
        pthread_attr_t attr;
        int r;

        r = pthread_attr_init(&attr);
        if (r < 0) {
                return log_error_errno(errno, "Cannot initialize pthread attributes: %m");
        }

        r = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (r < 0) {
                r = log_error_errno(errno, "Cannot mark pthread attributes as detached: %m");
                goto finish;
        }

        r = shared_policy_new(&sp);
        if (r < 0)
                goto finish;

        for (;;) {
                ClientContext *c;
                pthread_t tid;
                int fd;

                fd = accept4(accept_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
                if (fd < 0) {
                        if (errno == EAGAIN || errno == EINTR)
                                continue;

                        r = log_error_errno(errno, "accept4() failed: %m");
                        goto finish;
                }

                r = client_context_new(&c);
                if (r < 0) {
                        log_oom();
                        close(fd);
                        continue;
                }

                c->fd = fd;
                c->policy = sp;
                c->bus_uid = bus_uid;

                r = pthread_create(&tid, &attr, run_client, c);
                if (r < 0) {
                        log_error("Cannot spawn thread: %m");
                        client_context_free(c);
                        continue;
                }
        }

finish:
        pthread_attr_destroy(&attr);
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

                case ARG_ADDRESS:
                        r = free_and_strdup(&arg_address, optarg);
                        if (r < 0)
                                return log_oom();
                        break;

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

                        a = strjoin("x-machine-kernel:machine=", e, ";x-machine-unix:machine=", e, NULL);
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
        uid_t uid, bus_uid;
        gid_t gid;

        log_set_target(LOG_TARGET_JOURNAL_OR_KMSG);
        log_parse_environment();
        log_open();

        bus_uid = getuid();

        if (geteuid() == 0) {
                const char *user = "systemd-bus-proxy";

                r = get_user_creds(&user, &uid, &gid, NULL, NULL);
                if (r < 0) {
                        log_error_errno(r, "Cannot resolve user name %s: %m", user);
                        goto finish;
                }

                r = drop_privileges(uid, gid, 1ULL << CAP_IPC_OWNER);
                if (r < 0) {
                        log_error_errno(r, "Cannot drop privileges: %m");
                        goto finish;
                }
        }

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

        r = loop_clients(accept_fd, bus_uid);

finish:
        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Shutting down.");

        strv_free(arg_configuration);
        free(arg_address);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
