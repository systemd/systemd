/* SPDX-License-Identifier: LGPL-2.1+ */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "def.h"
#include "fd-util.h"
#include "format-util.h"
#include "initreq.h"
#include "list.h"
#include "log.h"
#include "memory-util.h"
#include "process-util.h"
#include "special.h"

#define SERVER_FD_MAX 16
#define TIMEOUT_MSEC ((int) (DEFAULT_EXIT_USEC/USEC_PER_MSEC))

typedef struct Fifo Fifo;

typedef struct Server {
        int epoll_fd;

        LIST_HEAD(Fifo, fifos);
        unsigned n_fifos;

        sd_bus *bus;

        bool quit;
} Server;

struct Fifo {
        Server *server;

        int fd;

        struct init_request buffer;
        size_t bytes_read;

        LIST_FIELDS(Fifo, fifo);
};

static const char *translate_runlevel(int runlevel, bool *isolate) {
        static const struct {
                const int runlevel;
                const char *special;
                bool isolate;
        } table[] = {
                { '0', SPECIAL_POWEROFF_TARGET,   false },
                { '1', SPECIAL_RESCUE_TARGET,     true  },
                { 's', SPECIAL_RESCUE_TARGET,     true  },
                { 'S', SPECIAL_RESCUE_TARGET,     true  },
                { '2', SPECIAL_MULTI_USER_TARGET, true  },
                { '3', SPECIAL_MULTI_USER_TARGET, true  },
                { '4', SPECIAL_MULTI_USER_TARGET, true  },
                { '5', SPECIAL_GRAPHICAL_TARGET,  true  },
                { '6', SPECIAL_REBOOT_TARGET,     false },
        };

        unsigned i;

        assert(isolate);

        for (i = 0; i < ELEMENTSOF(table); i++)
                if (table[i].runlevel == runlevel) {
                        *isolate = table[i].isolate;
                        if (runlevel == '6' && kexec_loaded())
                                return SPECIAL_KEXEC_TARGET;
                        return table[i].special;
                }

        return NULL;
}

static int change_runlevel(Server *s, int runlevel) {
        const char *target;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *mode;
        bool isolate = false;
        int r;

        assert(s);

        target = translate_runlevel(runlevel, &isolate);
        if (!target) {
                log_warning("Got request for unknown runlevel %c, ignoring.", runlevel);
                return 0;
        }

        if (isolate)
                mode = "isolate";
        else
                mode = "replace-irreversibly";

        log_debug("Running request %s/start/%s", target, mode);

        r = sd_bus_call_method(
                        s->bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartUnit",
                        &error,
                        NULL,
                        "ss", target, mode);
        if (r < 0)
                return log_error_errno(r, "Failed to change runlevel: %s", bus_error_message(&error, -r));

        return 0;
}

static void request_process(Server *s, const struct init_request *req) {
        assert(s);
        assert(req);

        if (req->magic != INIT_MAGIC) {
                log_error("Got initctl request with invalid magic. Ignoring.");
                return;
        }

        switch (req->cmd) {

        case INIT_CMD_RUNLVL:
                if (!isprint(req->runlevel))
                        log_error("Got invalid runlevel. Ignoring.");
                else
                        switch (req->runlevel) {

                        /* we are async anyway, so just use kill for reexec/reload */
                        case 'u':
                        case 'U':
                                if (kill(1, SIGTERM) < 0)
                                        log_error_errno(errno, "kill() failed: %m");

                                /* The bus connection will be
                                 * terminated if PID 1 is reexecuted,
                                 * hence let's just exit here, and
                                 * rely on that we'll be restarted on
                                 * the next request */
                                s->quit = true;
                                break;

                        case 'q':
                        case 'Q':
                                if (kill(1, SIGHUP) < 0)
                                        log_error_errno(errno, "kill() failed: %m");
                                break;

                        default:
                                (void) change_runlevel(s, req->runlevel);
                        }
                return;

        case INIT_CMD_POWERFAIL:
        case INIT_CMD_POWERFAILNOW:
        case INIT_CMD_POWEROK:
                log_warning("Received UPS/power initctl request. This is not implemented in systemd. Upgrade your UPS daemon!");
                return;

        case INIT_CMD_CHANGECONS:
                log_warning("Received console change initctl request. This is not implemented in systemd.");
                return;

        case INIT_CMD_SETENV:
        case INIT_CMD_UNSETENV:
                log_warning("Received environment initctl request. This is not implemented in systemd.");
                return;

        default:
                log_warning("Received unknown initctl request. Ignoring.");
                return;
        }
}

static int fifo_process(Fifo *f) {
        ssize_t l;

        assert(f);

        errno = EIO;
        l = read(f->fd,
                 ((uint8_t*) &f->buffer) + f->bytes_read,
                 sizeof(f->buffer) - f->bytes_read);
        if (l <= 0) {
                if (errno == EAGAIN)
                        return 0;

                return log_warning_errno(errno, "Failed to read from fifo: %m");
        }

        f->bytes_read += l;
        assert(f->bytes_read <= sizeof(f->buffer));

        if (f->bytes_read == sizeof(f->buffer)) {
                request_process(f->server, &f->buffer);
                f->bytes_read = 0;
        }

        return 0;
}

static void fifo_free(Fifo *f) {
        assert(f);

        if (f->server) {
                assert(f->server->n_fifos > 0);
                f->server->n_fifos--;
                LIST_REMOVE(fifo, f->server->fifos, f);
        }

        if (f->fd >= 0) {
                if (f->server)
                        epoll_ctl(f->server->epoll_fd, EPOLL_CTL_DEL, f->fd, NULL);

                safe_close(f->fd);
        }

        free(f);
}

static void server_done(Server *s) {
        assert(s);

        while (s->fifos)
                fifo_free(s->fifos);

        s->epoll_fd = safe_close(s->epoll_fd);
        s->bus = sd_bus_flush_close_unref(s->bus);
}

static int server_init(Server *s, unsigned n_sockets) {
        int r;
        unsigned i;

        assert(s);
        assert(n_sockets > 0);

        zero(*s);

        s->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (s->epoll_fd < 0) {
                r = log_error_errno(errno,
                                    "Failed to create epoll object: %m");
                goto fail;
        }

        for (i = 0; i < n_sockets; i++) {
                struct epoll_event ev;
                Fifo *f;
                int fd;

                fd = SD_LISTEN_FDS_START+i;

                r = sd_is_fifo(fd, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to determine file descriptor type: %m");
                        goto fail;
                }

                if (!r) {
                        log_error("Wrong file descriptor type.");
                        r = -EINVAL;
                        goto fail;
                }

                f = new0(Fifo, 1);
                if (!f) {
                        r = -ENOMEM;
                        log_error_errno(errno, "Failed to create fifo object: %m");
                        goto fail;
                }

                f->fd = -1;

                zero(ev);
                ev.events = EPOLLIN;
                ev.data.ptr = f;
                if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                        r = -errno;
                        fifo_free(f);
                        log_error_errno(errno, "Failed to add fifo fd to epoll object: %m");
                        goto fail;
                }

                f->fd = fd;
                LIST_PREPEND(fifo, s->fifos, f);
                f->server = s;
                s->n_fifos++;
        }

        r = bus_connect_system_systemd(&s->bus);
        if (r < 0) {
                log_error_errno(r, "Failed to get D-Bus connection: %m");
                r = -EIO;
                goto fail;
        }

        return 0;

fail:
        server_done(s);

        return r;
}

static int process_event(Server *s, struct epoll_event *ev) {
        int r;
        Fifo *f;

        assert(s);

        if (!(ev->events & EPOLLIN))
                return log_info_errno(SYNTHETIC_ERRNO(EIO),
                                      "Got invalid event from epoll. (3)");

        f = (Fifo*) ev->data.ptr;
        r = fifo_process(f);
        if (r < 0) {
                log_info_errno(r, "Got error on fifo: %m");
                fifo_free(f);
                return r;
        }

        return 0;
}

int main(int argc, char *argv[]) {
        Server server;
        int r = EXIT_FAILURE, n;

        if (getppid() != 1) {
                log_error("This program should be invoked by init only.");
                return EXIT_FAILURE;
        }

        if (argc > 1) {
                log_error("This program does not take arguments.");
                return EXIT_FAILURE;
        }

        log_setup_service();

        umask(0022);

        n = sd_listen_fds(true);
        if (n < 0) {
                log_error_errno(r, "Failed to read listening file descriptors from environment: %m");
                return EXIT_FAILURE;
        }

        if (n <= 0 || n > SERVER_FD_MAX) {
                log_error("No or too many file descriptors passed.");
                return EXIT_FAILURE;
        }

        if (server_init(&server, (unsigned) n) < 0)
                return EXIT_FAILURE;

        log_debug("systemd-initctl running as pid "PID_FMT, getpid_cached());

        sd_notify(false,
                  "READY=1\n"
                  "STATUS=Processing requests...");

        while (!server.quit) {
                struct epoll_event event;
                int k;

                k = epoll_wait(server.epoll_fd, &event, 1, TIMEOUT_MSEC);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;
                        log_error_errno(errno, "epoll_wait() failed: %m");
                        goto fail;
                }

                if (k <= 0)
                        break;

                if (process_event(&server, &event) < 0)
                        goto fail;
        }

        r = EXIT_SUCCESS;

        log_debug("systemd-initctl stopped as pid "PID_FMT, getpid_cached());

fail:
        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Shutting down...");

        server_done(&server);

        return r;
}
