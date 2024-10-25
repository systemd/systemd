/* SPDX-License-Identifier: LGPL-2.1-or-later */

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
#include "bus-locator.h"
#include "bus-util.h"
#include "constants.h"
#include "daemon-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "initreq.h"
#include "list.h"
#include "log.h"
#include "main-func.h"
#include "memory-util.h"
#include "process-util.h"
#include "reboot-util.h"
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

        assert(isolate);

        FOREACH_ELEMENT(i, table)
                if (i->runlevel == runlevel) {
                        *isolate = i->isolate;
                        if (runlevel == '6' && kexec_loaded())
                                return SPECIAL_KEXEC_TARGET;
                        return i->special;
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

        log_debug("Requesting %s/start/%s", target, mode);

        r = bus_call_method(s->bus, bus_systemd_mgr, "StartUnit", &error, NULL, "ss", target, mode);
        if (r < 0)
                return log_error_errno(r, "Failed to change runlevel: %s", bus_error_message(&error, r));

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

static Fifo* fifo_free(Fifo *f) {
        if (!f)
                return NULL;

        if (f->server) {
                assert(f->server->n_fifos > 0);
                f->server->n_fifos--;
                LIST_REMOVE(fifo, f->server->fifos, f);
        }

        if (f->fd >= 0) {
                if (f->server)
                        (void) epoll_ctl(f->server->epoll_fd, EPOLL_CTL_DEL, f->fd, NULL);

                safe_close(f->fd);
        }

        return mfree(f);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(Fifo*, fifo_free);

static void server_done(Server *s) {
        assert(s);

        while (s->fifos)
                fifo_free(s->fifos);

        s->epoll_fd = safe_close(s->epoll_fd);
        s->bus = sd_bus_flush_close_unref(s->bus);
}

static int server_init(Server *s, unsigned n_sockets) {
        int r;

        /* This function will leave s partially initialized on failure. Caller needs to clean up. */

        assert(s);
        assert(n_sockets > 0);

        s->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (s->epoll_fd < 0)
                return log_error_errno(errno, "Failed to create epoll object: %m");

        for (unsigned i = 0; i < n_sockets; i++) {
                _cleanup_(fifo_freep) Fifo *f = NULL;
                int fd = SD_LISTEN_FDS_START + i;

                r = sd_is_fifo(fd, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine file descriptor type: %m");
                if (!r)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Wrong file descriptor type.");

                f = new0(Fifo, 1);
                if (!f)
                        return log_oom();

                struct epoll_event ev = {
                        .events = EPOLLIN,
                        .data.ptr = f,
                };

                if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
                        return log_error_errno(errno, "Failed to add fifo fd to epoll object: %m");

                f->fd = fd;
                f->server = s;
                LIST_PREPEND(fifo, s->fifos, TAKE_PTR(f));
                s->n_fifos++;
        }

        r = bus_connect_system_systemd(&s->bus);
        if (r < 0)
                return log_error_errno(r, "Failed to get D-Bus connection: %m");

        return 0;
}

static int process_event(Server *s, struct epoll_event *ev) {
        int r;
        _cleanup_(fifo_freep) Fifo *f = NULL;

        assert(s);
        assert(ev);

        if (!(ev->events & EPOLLIN))
                return log_info_errno(SYNTHETIC_ERRNO(EIO),
                                      "Got invalid event from epoll. (3)");

        f = (Fifo*) ev->data.ptr;
        r = fifo_process(f);
        if (r < 0)
                return log_info_errno(r, "Got error on fifo: %m");

        TAKE_PTR(f);

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(server_done) Server server = { .epoll_fd = -EBADF };
        _unused_ _cleanup_(notify_on_cleanup) const char *notify_stop = NULL;
        int r, n;

        if (argc > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program does not take arguments.");

        log_setup();

        umask(0022);

        n = sd_listen_fds(true);
        if (n < 0)
                return log_error_errno(errno,
                                       "Failed to read listening file descriptors from environment: %m");

        if (n <= 0 || n > SERVER_FD_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No or too many file descriptors passed.");

        r = server_init(&server, (unsigned) n);
        if (r < 0)
                return r;

        notify_stop = notify_start(NOTIFY_READY, NOTIFY_STOPPING);

        while (!server.quit) {
                struct epoll_event event;
                int k;

                k = epoll_wait(server.epoll_fd, &event, 1, TIMEOUT_MSEC);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;
                        return log_error_errno(errno, "epoll_wait() failed: %m");
                }
                if (k == 0)
                        break;

                r = process_event(&server, &event);
                if (r < 0)
                        return r;
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
