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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "journal-file.h"
#include "journald-native.h"
#include "socket-util.h"
#include "mkdir.h"
#include "build.h"
#include "macro.h"
#include "strv.h"

#include "journal-remote-parse.h"
#include "journal-remote-write.h"

#define REMOTE_JOURNAL_PATH "/var/log/journal/" SD_ID128_FORMAT_STR "/remote-%s.journal"

static char* arg_output = NULL;
static char* arg_url = NULL;
static char* arg_getter = NULL;
static bool arg_stdin = false;
static char* arg_listen_raw = NULL;
static int arg_compress = true;
static int arg_seal = false;

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int spawn_child(const char* child, char** argv) {
        int fd[2];
        pid_t parent_pid, child_pid;
        int r;

        if (pipe(fd) < 0) {
                log_error("Failed to create pager pipe: %m");
                return -errno;
        }

        parent_pid = getpid();

        child_pid = fork();
        if (child_pid < 0) {
                r = -errno;
                log_error("Failed to fork: %m");
                close_pipe(fd);
                return r;
        }

        /* In the child */
        if (child_pid == 0) {
                r = dup2(fd[1], STDOUT_FILENO);
                if (r < 0) {
                        log_error("Failed to dup pipe to stdout: %m");
                        _exit(EXIT_FAILURE);
                }

                r = close_pipe(fd);
                if (r < 0)
                        log_warning("Failed to close pipe fds: %m");

                /* Make sure the child goes away when the parent dies */
                if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
                        _exit(EXIT_FAILURE);

                /* Check whether our parent died before we were able
                 * to set the death signal */
                if (getppid() != parent_pid)
                        _exit(EXIT_SUCCESS);

                execvp(child, argv);
                log_error("Failed to exec child %s: %m", child);
                _exit(EXIT_FAILURE);
        }

        r = close(fd[1]);
        if (r < 0)
                log_warning("Failed to close write end of pipe: %m");

        return fd[0];
}

static int spawn_curl(char* url) {
        char **argv = STRV_MAKE("curl",
                                "-HAccept: application/vnd.fdo.journal",
                                "--silent",
                                "--show-error",
                                url);
        int r;

        r = spawn_child("curl", argv);
        if (r < 0)
                log_error("Failed to spawn curl: %m");
        return r;
}

static int spawn_getter(char *getter, char *url) {
        int r;
        char _cleanup_strv_free_ **words = NULL, **words2 = NULL;

        assert(getter);
        words = strv_split_quoted(getter);
        if (!words)
                return log_oom();

        r = spawn_child(words[0], words);
        if (r < 0)
                log_error("Failed to spawn getter %s: %m", getter);

        return r;
}

static int open_output(Writer *s, const char* url) {
        char _cleanup_free_ *name, *output = NULL;
        char *c;
        int r;

        assert(url);
        name = strdup(url);
        if (!name)
                return log_oom();

        for(c = name; *c; c++) {
                if (*c == '/' || *c == ':' || *c == ' ')
                        *c = '~';
                else if (*c == '?') {
                        *c = '\0';
                        break;
                }
        }

        if (!arg_output) {
                sd_id128_t machine;
                r = sd_id128_get_machine(&machine);
                if (r < 0) {
                        log_error("failed to determine machine ID128: %s", strerror(-r));
                        return r;
                }

                r = asprintf(&output, REMOTE_JOURNAL_PATH,
                             SD_ID128_FORMAT_VAL(machine), name);
                if (r < 0)
                        return log_oom();
        } else {
                r = is_dir(arg_output);
                if (r > 0) {
                        r = asprintf(&output,
                                     "%s/remote-%s.journal", arg_output, name);
                        if (r < 0)
                                return log_oom();
                } else {
                        output = strdup(arg_output);
                        if (!output)
                                return log_oom();
                }
        }

        r = journal_file_open_reliably(output,
                                       O_RDWR|O_CREAT, 0640,
                                       arg_compress, arg_seal,
                                       &s->metrics,
                                       s->mmap,
                                       NULL, &s->journal);
        if (r < 0)
                log_error("Failed to open output journal %s: %s",
                          arg_output, strerror(-r));
        else
                log_info("Opened output file %s", s->journal->path);
        return r;
}

typedef struct RemoteServer {
        RemoteSource **sources;
        ssize_t sources_size;
        ssize_t active;

        sd_event *events;
        sd_event_source *sigterm_event, *sigint_event, *listen_event;

        Writer writer;
} RemoteServer;

static int dispatch_raw_source_event(sd_event_source *event,
                                     int fd,
                                     uint32_t revents,
                                     void *userdata);
static int dispatch_raw_connection_event(sd_event_source *event,
                                         int fd,
                                         uint32_t revents,
                                         void *userdata);

static int get_source_for_fd(RemoteServer *s, int fd, RemoteSource **source) {
        assert(fd >= 0);
        assert(source);

        if (!GREEDY_REALLOC0_T(s->sources, s->sources_size, fd + 1))
                return log_oom();

        if (s->sources[fd] == NULL) {
                s->sources[fd] = new0(RemoteSource, 1);
                if (!s->sources[fd])
                        return log_oom();
                s->sources[fd]->fd = -1;
                s->active++;
        }

        *source = s->sources[fd];
        return 0;
}

static int remove_source(RemoteServer *s, int fd) {
        RemoteSource *source;

        assert(s);
        assert(fd >= 0);
        assert(fd < s->sources_size);

        source = s->sources[fd];
        if (source) {
                source_free(source);
                s->sources[fd] = NULL;
                s->active--;
        }

        close(fd);

        return 0;
}

static int add_source(RemoteServer *s, int fd, const char* name) {
        RemoteSource *source = NULL;
        char *realname;
        int r;

        assert(s);
        assert(fd >= 0);

        if (name) {
                realname = strdup(name);
                if (!realname)
                        return log_oom();
        } else {
                r = asprintf(&realname, "fd:%d", fd);
                if (r < 0)
                        return log_oom();
        }

        log_debug("Creating source for fd:%d (%s)", fd, name);

        r = get_source_for_fd(s, fd, &source);
        if (r < 0) {
                log_error("Failed to create source for fd:%d (%s)", fd, name);
                return r;
        }
        assert(source);
        assert(source->fd < 0);
        source->fd = fd;

        r = sd_event_add_io(s->events, &source->event,
                            fd, EPOLLIN, dispatch_raw_source_event, s);
        if (r < 0) {
                log_error("Failed to register event source for fd:%d: %s",
                          fd, strerror(-r));
                goto error;
        }

        return 1; /* work to do */

 error:
        remove_source(s, fd);
        return r;
}

static int setup_raw_socket(RemoteServer *s, const char *address) {
        int fd, r;

        fd = make_socket_fd(LOG_INFO, address, SOCK_STREAM | SOCK_CLOEXEC);
        if (fd < 0)
                return fd;

        r = sd_event_add_io(s->events, &s->listen_event, fd, EPOLLIN,
                            dispatch_raw_connection_event, s);
        if (r < 0) {
                close(fd);
                return r;
        }

        s->active ++;
        return 0;
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int dispatch_sigterm(sd_event_source *event,
                            const struct signalfd_siginfo *si,
                            void *userdata) {
        RemoteServer *s = userdata;

        assert(s);

        log_received_signal(LOG_INFO, si);

        sd_event_exit(s->events, 0);
        return 0;
}

static int setup_signals(RemoteServer *s) {
        sigset_t mask;
        int r;

        assert(s);

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGINT, SIGTERM, -1);
        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

        r = sd_event_add_signal(s->events, &s->sigterm_event, SIGTERM, dispatch_sigterm, s);
        if (r < 0)
                return r;

        r = sd_event_add_signal(s->events, &s->sigint_event, SIGINT, dispatch_sigterm, s);
        if (r < 0)
                return r;

        return 0;
}

static int remoteserver_init(RemoteServer *s) {
        int r, n, fd;
        const char *output_name = NULL;

        assert(s);

        sd_event_default(&s->events);

        setup_signals(s);

        n = sd_listen_fds(true);
        if (n < 0) {
                log_error("Failed to read listening file descriptors from environment: %s",
                          strerror(-n));
                return n;
        } else
                log_info("Received %d descriptors", n);

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
                if (sd_is_socket(fd, AF_UNSPEC, 0, false)) {
                        assert_not_reached("not implemented");
                } else if (sd_is_socket(fd, AF_UNSPEC, 0, true)) {
                        log_info("Received a connection socket (fd:%d)", fd);

                        r = add_source(s, fd, NULL);
                        output_name = "socket";
                } else {
                        log_error("Unknown socket passed on fd:%d", fd);
                        return -EINVAL;
                }
        }

        if (arg_url) {
                char _cleanup_free_ *url = NULL;
                char _cleanup_strv_free_ **urlv = strv_new(arg_url, "/entries", NULL);
                if (!urlv)
                        return log_oom();
                url = strv_join(urlv, "");
                if (!url)
                        return log_oom();

                if (arg_getter) {
                        log_info("Spawning getter %s...", url);
                        fd = spawn_getter(arg_getter, url);
                } else {
                        log_info("Spawning curl %s...", url);
                        fd = spawn_curl(url);
                }
                if (fd < 0)
                        return fd;

                r = add_source(s, fd, arg_url);
                if (r < 0)
                        return r;

                output_name = arg_url;
        }

        if (arg_listen_raw) {
                log_info("Listening on a socket...");
                r = setup_raw_socket(s, arg_listen_raw);
                if (r < 0)
                        return r;

                output_name = arg_listen_raw;
        }

        if (arg_stdin) {
                log_info("Reading standard input...");
                r = add_source(s, STDIN_FILENO, "stdin");
                if (r < 0)
                        return r;

                output_name = "stdin";
        }

        if (s->active == 0) {
                log_error("Zarro sources specified");
                return -EINVAL;
        }

        if (!!n + !!arg_url + !!arg_listen_raw + !!arg_stdin > 1)
                output_name = "multiple";

        r = writer_init(&s->writer);
        if (r < 0)
                return r;

        r = open_output(&s->writer, output_name);
        return r;
}

static int server_destroy(RemoteServer *s) {
        int r;
        ssize_t i;

        r = writer_close(&s->writer);

        assert(s->sources_size == 0 || s->sources);
        for(i = 0; i < s->sources_size; i++)
                remove_source(s, i);

        free(s->sources);

        sd_event_source_unref(s->sigterm_event);
        sd_event_source_unref(s->sigint_event);
        sd_event_source_unref(s->listen_event);
        sd_event_unref(s->events);

        /* fds that we're listening on remain open... */

        return r;
}

/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int dispatch_raw_source_event(sd_event_source *event,
                                     int fd,
                                     uint32_t revents,
                                     void *userdata) {

        RemoteServer *s = userdata;
        RemoteSource *source;
        int r;

        assert(fd < s->sources_size);
        source = s->sources[fd];
        assert(source->fd == fd);

        r = process_source(source, &s->writer, arg_compress, arg_seal);
        if (source->state == STATE_EOF) {
                log_info("EOF reached with source fd:%d (%s)",
                         source->fd, source->name);
                if (source_non_empty(source))
                        log_warning("EOF reached with incomplete data");
                remove_source(s, source->fd);
                log_info("%zd active source remaining", s->active);
        } else if (r == -E2BIG) {
                log_error("Entry too big, skipped");
                r = 1;
        }

        return r;
}

static int dispatch_raw_connection_event(sd_event_source *event,
                                         int fd,
                                         uint32_t revents,
                                         void *userdata) {
        RemoteServer *s = userdata;

        SocketAddress addr = {
                .size = sizeof(union sockaddr_union),
                .type = SOCK_STREAM,
        };
        int fd2, r;

        log_debug("Accepting new connection on fd:%d", fd);
        fd2 = accept4(fd, &addr.sockaddr.sa, &addr.size, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (fd2 < 0) {
                log_error("accept() on fd:%d failed: %m", fd);
                return -errno;
        }

        switch(socket_address_family(&addr)) {
        case AF_INET:
        case AF_INET6: {
                char* _cleanup_free_ a = NULL;

                r = socket_address_print(&addr, &a);
                if (r < 0) {
                        log_error("socket_address_print(): %s", strerror(-r));
                        close(fd2);
                        return r;
                }

                log_info("Accepted %s connection from %s",
                         socket_address_family(&addr) == AF_INET ? "IP" : "IPv6",
                         a);
                break;
        };
        default:
                log_error("Connection with unsupported family %d",
                          socket_address_family(&addr));
                close(fd2);
                return -EINVAL;
        }

        r = add_source(s, fd2, NULL);
        if (r < 0)
                log_error("failed to create source from fd:%d: %s", fd2, strerror(-r));

        return r;
}


/**********************************************************************
 **********************************************************************
 **********************************************************************/

static int help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Write external journal events to a journal file.\n\n"
               "Options:\n"
               "  --url=URL            Read events from systemd-journal-gatewayd at URL\n"
               "  --getter=COMMAND     Read events from the output of COMMAND\n"
               "  --listen-raw=ADDR    Listen for connections at ADDR\n"
               "  --stdin              Read events from standard input\n"
               "  -o --output=FILE|DIR Write output to FILE or DIR/external-*.journal\n"
               "  --[no-]compress      Use XZ-compression in the output journal (default: yes)\n"
               "  --[no-]seal          Use Event sealing in the output journal (default: no)\n"
               "  -h --help            Show this help and exit\n"
               "  --version            Print version string and exit\n"
               "\n"
               "Note: file descriptors from sd_listen_fds() will be consumed, too.\n"
               , program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_URL,
                ARG_LISTEN_RAW,
                ARG_STDIN,
                ARG_GETTER,
                ARG_COMPRESS,
                ARG_NO_COMPRESS,
                ARG_SEAL,
                ARG_NO_SEAL,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "url",          required_argument, NULL, ARG_URL          },
                { "getter",       required_argument, NULL, ARG_GETTER       },
                { "listen-raw",   required_argument, NULL, ARG_LISTEN_RAW   },
                { "stdin",        no_argument,       NULL, ARG_STDIN        },
                { "output",       required_argument, NULL, 'o'              },
                { "compress",     no_argument,       NULL, ARG_COMPRESS     },
                { "no-compress",  no_argument,       NULL, ARG_NO_COMPRESS  },
                { "seal",         no_argument,       NULL, ARG_SEAL         },
                { "no-seal",      no_argument,       NULL, ARG_NO_SEAL      },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "ho:", options, NULL)) >= 0)
                switch(c) {
                case 'h':
                        help();
                        return 0 /* done */;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0 /* done */;

                case ARG_URL:
                        if (arg_url) {
                                log_error("cannot currently set more than one --url");
                                return -EINVAL;
                        }

                        arg_url = optarg;
                        break;

                case ARG_GETTER:
                        if (arg_getter) {
                                log_error("cannot currently use --getter more than once");
                                return -EINVAL;
                        }

                        arg_getter = optarg;
                        break;

                case ARG_LISTEN_RAW:
                        if (arg_listen_raw) {
                                log_error("cannot currently use --listen-raw more than once");
                                return -EINVAL;
                        }

                        arg_listen_raw = optarg;
                        break;

                case ARG_STDIN:
                        arg_stdin = true;
                        break;

                case 'o':
                        if (arg_output) {
                                log_error("cannot use --output/-o more than once");
                                return -EINVAL;
                        }

                        arg_output = optarg;
                        break;

                case ARG_COMPRESS:
                        arg_compress = true;
                        break;
                case ARG_NO_COMPRESS:
                        arg_compress = false;
                        break;
                case ARG_SEAL:
                        arg_seal = true;
                        break;
                case ARG_NO_SEAL:
                        arg_seal = false;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }

        if (optind < argc) {
                log_error("This program takes no positional arguments");
                return -EINVAL;
        }

        return 1 /* work to do */;
}

int main(int argc, char **argv) {
        RemoteServer s = {};
        int r, r2;

        log_set_max_level(LOG_DEBUG);
        log_show_color(true);
        log_parse_environment();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;

        if (remoteserver_init(&s) < 0)
                return EXIT_FAILURE;

        log_debug("%s running as pid %lu",
                  program_invocation_short_name, (unsigned long) getpid());
        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        while (s.active) {
                r = sd_event_get_state(s.events);
                if (r < 0)
                        break;
                if (r == SD_EVENT_FINISHED)
                        break;

                r = sd_event_run(s.events, -1);
                if (r < 0) {
                        log_error("Failed to run event loop: %s", strerror(-r));
                        break;
                }
        }

        log_info("Finishing after writing %" PRIu64 " entries", s.writer.seqnum);
        r2 = server_destroy(&s);

        sd_notify(false, "STATUS=Shutting down...");

        return r >= 0 && r2 >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
