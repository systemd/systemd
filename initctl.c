/*-*- Mode: C; c-basic-offset: 8 -*-*/

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

#include <sys/socket.h>
#include <sys/types.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <fcntl.h>
#include <ctype.h>

#include <dbus/dbus.h>

#include "util.h"
#include "log.h"
#include "list.h"
#include "initreq.h"

#define SERVER_FD_START 3
#define SERVER_FD_MAX 16
#define TIMEOUT ((int) (10*MSEC_PER_SEC))

typedef struct Fifo Fifo;

typedef struct Server {
        int epoll_fd;

        LIST_HEAD(Fifo, fifos);
        unsigned n_fifos;

        DBusConnection *bus;
} Server;

struct Fifo {
        Server *server;

        int fd;

        struct init_request buffer;
        size_t bytes_read;

        LIST_FIELDS(Fifo, fifo);
};

static const char *translate_runlevel(int runlevel) {

        switch (runlevel) {

        case '0':
                return "halt.target";

        case '1':
        case 's':
        case 'S':
                return "rescue.target";

        case '2':
                return "runlevel2.target";

        case '3':
                return "runlevel3.target";

        case '4':
                return "runlevel4.target";

        case '5':
                return "runlevel5.target";

        case '6':
                return "reboot.target";

        default:
                return NULL;
        }
}

static void change_runlevel(Server *s, int runlevel) {
        const char *target;
        DBusMessage *m = NULL, *reply = NULL;
        DBusError error;
        const char *path, *replace = "replace";

        assert(s);

        dbus_error_init(&error);

        if (!(target = translate_runlevel(runlevel))) {
                log_warning("Got request for unknown runlevel %c, ignoring.", runlevel);
                goto finish;
        }

        log_debug("Running request %s", target);

        if (!(m = dbus_message_new_method_call("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1", "GetUnit"))) {
                log_error("Could not allocate message.");
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &target,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not attach group information to signal message.");
                goto finish;
        }

        if (!(reply = dbus_connection_send_with_reply_and_block(s->bus, m, -1, &error))) {
                log_error("Failed to get unit path: %s", error.message);
                goto finish;
        }

        if (!dbus_message_get_args(reply, &error,
                                   DBUS_TYPE_OBJECT_PATH, &path,
                                   DBUS_TYPE_INVALID)) {
                log_error("Failed to parse unit path: %s", error.message);
                goto finish;
        }

        dbus_message_unref(m);
        if (!(m = dbus_message_new_method_call("org.freedesktop.systemd1", path, "org.freedesktop.systemd1.Unit", "Start"))) {
                log_error("Could not allocate message.");
                goto finish;
        }

        if (!dbus_message_append_args(m,
                                      DBUS_TYPE_STRING, &replace,
                                      DBUS_TYPE_INVALID)) {
                log_error("Could not attach group information to signal message.");
                goto finish;
        }

        dbus_message_unref(reply);
        if (!(reply = dbus_connection_send_with_reply_and_block(s->bus, m, -1, &error))) {
                log_error("Failed to start unit: %s", error.message);
                goto finish;
        }

finish:
        if (m)
                dbus_message_unref(m);

        if (reply)
                dbus_message_unref(reply);

        dbus_error_free(&error);
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
                        change_runlevel(s, req->runlevel);
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
        if ((l = read(f->fd, ((uint8_t*) &f->buffer) + f->bytes_read, sizeof(f->buffer) - f->bytes_read)) <= 0) {

                if (errno == EAGAIN)
                        return 0;

                log_warning("Failed to read from fifo: %s", strerror(errno));
                return -1;
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
                LIST_REMOVE(Fifo, fifo, f->server->fifos, f);
        }

        if (f->fd >= 0) {
                if (f->server)
                        epoll_ctl(f->server->epoll_fd, EPOLL_CTL_DEL, f->fd, NULL);

                close_nointr_nofail(f->fd);
        }

        free(f);
}

static int verify_environment(unsigned *n_sockets) {
        unsigned long long pid;
        const char *e;
        int r;
        unsigned ns;

        assert_se(n_sockets);

        if (!(e = getenv("LISTEN_PID"))) {
                log_error("Missing $LISTEN_PID environment variable.");
                return -ENOENT;
        }

        if ((r = safe_atollu(e, &pid)) < 0) {
                log_error("Failed to parse $LISTEN_PID: %s", strerror(-r));
                return r;
        }

        if (pid != (unsigned long long) getpid()) {
                log_error("Socket nor for me.");
                return -ENOENT;
        }

        if (!(e = getenv("LISTEN_FDS"))) {
                log_error("Missing $LISTEN_FDS environment variable.");
                return -ENOENT;
        }

        if ((r = safe_atou(e, &ns)) < 0) {
                log_error("Failed to parse $LISTEN_FDS: %s", strerror(-r));
                return -E2BIG;
        }

        if (ns <= 0 || ns > SERVER_FD_MAX) {
                log_error("Wrong number of file descriptors passed: %s", e);
                return -E2BIG;
        }

        *n_sockets = ns;

        return 0;
}

static void server_done(Server *s) {
        assert(s);

        while (s->fifos)
                fifo_free(s->fifos);

        if (s->epoll_fd >= 0)
                close_nointr_nofail(s->epoll_fd);

        if (s->bus)
                dbus_connection_unref(s->bus);
}

static int server_init(Server *s, unsigned n_sockets) {
        int r;
        unsigned i;
        DBusError error;

        assert(s);
        assert(n_sockets > 0);

        dbus_error_init(&error);

        zero(*s);

        if ((s->epoll_fd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
                r = -errno;
                log_error("Failed to create epoll object: %s", strerror(errno));
                goto fail;
        }

        for (i = 0; i < n_sockets; i++) {
                struct epoll_event ev;
                Fifo *f;

                if (!(f = new0(Fifo, 1))) {
                        r = -ENOMEM;
                        log_error("Failed to create fifo object: %s", strerror(errno));
                        goto fail;
                }

                f->fd = -1;

                zero(ev);
                ev.events = EPOLLIN;
                ev.data.ptr = f;
                if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, SERVER_FD_START+i, &ev) < 0) {
                        r = -errno;
                        fifo_free(f);
                        log_error("Failed to add fifo fd to epoll object: %s", strerror(errno));
                        goto fail;
                }

                f->fd = SERVER_FD_START+i;
                LIST_PREPEND(Fifo, fifo, s->fifos, f);
                f->server = s;
                s->n_fifos ++;
        }

        if (!(s->bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error))) {
                log_error("Failed to get D-Bus connection: %s", error.message);
                goto fail;
        }

        return 0;

fail:
        server_done(s);

        dbus_error_free(&error);
        return r;
}

static int process_event(Server *s, struct epoll_event *ev) {
        int r;
        Fifo *f;

        assert(s);

        if (!(ev->events & EPOLLIN)) {
                log_info("Got invalid event from epoll. (3)");
                return -EIO;
        }

        f = (Fifo*) ev->data.ptr;

        if ((r = fifo_process(f)) < 0) {
                log_info("Got error on fifo: %s", strerror(-r));
                fifo_free(f);
                return r;
        }

        return 0;
}

int main(int argc, char *argv[]) {
        Server server;
        int r = 3;
        unsigned n;

        log_info("systemd-initctl running as pid %llu", (unsigned long long) getpid());

        if (verify_environment(&n) < 0)
                return 1;

        if (server_init(&server, n) < 0)
                return 2;

        for (;;) {
                struct epoll_event event;
                int k;

                if ((k = epoll_wait(server.epoll_fd,
                                    &event, 1,
                                    TIMEOUT)) < 0) {

                        if (errno == EINTR)
                                continue;

                        log_error("epoll_wait() failed: %s", strerror(errno));
                        goto fail;
                }

                if (k <= 0)
                        break;

                if ((k = process_event(&server, &event)) < 0)
                        goto fail;
        }
        r = 0;

fail:
        server_done(&server);

        log_info("systemd-initctl stopped as pid %llu", (unsigned long long) getpid());

        dbus_shutdown();

        return r;
}
