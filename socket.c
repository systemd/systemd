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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <signal.h>

#include "unit.h"
#include "socket.h"
#include "log.h"

static const UnitActiveState state_translation_table[_SOCKET_STATE_MAX] = {
        [SOCKET_DEAD] = UNIT_INACTIVE,
        [SOCKET_START_PRE] = UNIT_ACTIVATING,
        [SOCKET_START_POST] = UNIT_ACTIVATING,
        [SOCKET_LISTENING] = UNIT_ACTIVE,
        [SOCKET_RUNNING] = UNIT_ACTIVE,
        [SOCKET_STOP_PRE] = UNIT_DEACTIVATING,
        [SOCKET_STOP_PRE_SIGTERM] = UNIT_DEACTIVATING,
        [SOCKET_STOP_PRE_SIGKILL] = UNIT_DEACTIVATING,
        [SOCKET_STOP_POST] = UNIT_DEACTIVATING,
        [SOCKET_STOP_POST_SIGTERM] = UNIT_DEACTIVATING,
        [SOCKET_STOP_POST_SIGKILL] = UNIT_DEACTIVATING,
        [SOCKET_MAINTAINANCE] = UNIT_INACTIVE,
};

static const char* const state_string_table[_SOCKET_STATE_MAX] = {
        [SOCKET_DEAD] = "dead",
        [SOCKET_START_PRE] = "start-pre",
        [SOCKET_START_POST] = "start-post",
        [SOCKET_LISTENING] = "listening",
        [SOCKET_RUNNING] = "running",
        [SOCKET_STOP_PRE] = "stop-pre",
        [SOCKET_STOP_PRE_SIGTERM] = "stop-pre-sigterm",
        [SOCKET_STOP_PRE_SIGKILL] = "stop-pre-sigkill",
        [SOCKET_STOP_POST] = "stop-post",
        [SOCKET_STOP_POST_SIGTERM] = "stop-post-sigterm",
        [SOCKET_STOP_POST_SIGKILL] = "stop-post-sigkill",
        [SOCKET_MAINTAINANCE] = "maintainance"
};

static void socket_done(Unit *u) {
        Socket *s = SOCKET(u);
        SocketPort *p;

        assert(s);

        while ((p = s->ports)) {
                LIST_REMOVE(SocketPort, port, s->ports, p);

                if (p->fd >= 0)
                        close_nointr(p->fd);
                free(p->path);
                free(p);
        }

        exec_context_done(&s->exec_context);
        exec_command_free_array(s->exec_command, _SOCKET_EXEC_MAX);
        s->control_command = NULL;

        if (s->control_pid > 0) {
                unit_unwatch_pid(u, s->control_pid);
                s->control_pid = 0;
        }

        s->service = NULL;

        free(s->bind_to_device);

        unit_unwatch_timer(u, &s->timer_watch);
}

static int socket_init(Unit *u) {
        Socket *s = SOCKET(u);
        char *t;
        int r;

        /* First, reset everything to the defaults, in case this is a
         * reload */

        s->state = 0;
        s->timer_watch.type = WATCH_INVALID;
        s->bind_ipv6_only = false;
        s->backlog = SOMAXCONN;
        s->timeout_usec = DEFAULT_TIMEOUT_USEC;
        exec_context_init(&s->exec_context);

        if ((r = unit_load_fragment_and_dropin(u)) <= 0) {
                if (r == 0)
                        r = -ENOENT;
                goto fail;
        }

        if (!(t = unit_name_change_suffix(unit_id(u), ".service"))) {
                r = -ENOMEM;
                goto fail;
        }

        r = manager_load_unit(u->meta.manager, t, (Unit**) &s->service);
        free(t);

        if (r < 0)
                goto fail;

        if ((r = unit_add_dependency(u, UNIT_BEFORE, UNIT(s->service))) < 0)
                goto fail;

        return 0;

fail:
        socket_done(u);
        return r;
}

static const char* listen_lookup(int type) {

        if (type == SOCK_STREAM)
                return "ListenStream";
        else if (type == SOCK_DGRAM)
                return "ListenDatagram";
        else if (type == SOCK_SEQPACKET)
                return "ListenSequentialPacket";

        assert_not_reached("Unknown socket type");
        return NULL;
}

static void socket_dump(Unit *u, FILE *f, const char *prefix) {

        static const char* const command_table[_SOCKET_EXEC_MAX] = {
                [SOCKET_EXEC_START_PRE] = "StartPre",
                [SOCKET_EXEC_START_POST] = "StartPost",
                [SOCKET_EXEC_STOP_PRE] = "StopPre",
                [SOCKET_EXEC_STOP_POST] = "StopPost"
        };

        SocketExecCommand c;
        Socket *s = SOCKET(u);
        SocketPort *p;
        const char *prefix2;
        char *p2;

        assert(s);
        assert(f);

        p2 = strappend(prefix, "\t");
        prefix2 = p2 ? p2 : prefix;

        fprintf(f,
                "%sSocket State: %s\n"
                "%sBindIPv6Only: %s\n"
                "%sBacklog: %u\n",
                prefix, state_string_table[s->state],
                prefix, yes_no(s->bind_ipv6_only),
                prefix, s->backlog);

        if (s->bind_to_device)
                fprintf(f,
                        "%sBindToDevice: %s\n",
                        prefix, s->bind_to_device);

        LIST_FOREACH(port, p, s->ports) {

                if (p->type == SOCKET_SOCKET) {
                        const char *t;
                        int r;
                        char *k;

                        if ((r = socket_address_print(&p->address, &k)) < 0)
                                t = strerror(-r);
                        else
                                t = k;

                        fprintf(f, "%s%s: %s\n", prefix, listen_lookup(p->address.type), k);
                        free(k);
                } else
                        fprintf(f, "%sListenFIFO: %s\n", prefix, p->path);
        }

        exec_context_dump(&s->exec_context, f, prefix);

        for (c = 0; c < _SOCKET_EXEC_MAX; c++) {
                if (!s->exec_command[c])
                        continue;

                fprintf(f, "%s→ %s:\n",
                        prefix, command_table[c]);

                exec_command_dump_list(s->exec_command[c], f, prefix2);
        }

        free(p2);
}

static void socket_close_fds(Socket *s) {
        SocketPort *p;

        assert(s);

        LIST_FOREACH(port, p, s->ports) {
                if (p->fd < 0)
                        continue;

                unit_unwatch_fd(UNIT(s), &p->fd_watch);
                assert_se(close_nointr(p->fd) >= 0);

                p->fd = -1;
        }
}

static int socket_open_fds(Socket *s) {
        SocketPort *p;
        int r;

        assert(s);

        LIST_FOREACH(port, p, s->ports) {

                if (p->fd >= 0)
                        continue;

                if (p->type == SOCKET_SOCKET) {

                        if ((r = socket_address_listen(&p->address, s->backlog, s->bind_ipv6_only, s->bind_to_device, &p->fd)) < 0)
                                goto rollback;

                } else {
                        struct stat st;
                        assert(p->type == SOCKET_FIFO);

                        if (mkfifo(p->path, 0666 & ~s->exec_context.umask) < 0 && errno != EEXIST) {
                                r = -errno;
                                goto rollback;
                        }

                        if ((p->fd = open(p->path, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK|O_NOFOLLOW)) < 0) {
                                r = -errno;
                                goto rollback;
                        }

                        if (fstat(p->fd, &st) < 0) {
                                r = -errno;
                                goto rollback;
                        }

                        /* FIXME verify user, access mode */

                        if (!S_ISFIFO(st.st_mode)) {
                                r = -EEXIST;
                                goto rollback;
                        }
                }
        }

        return 0;

rollback:
        socket_close_fds(s);
        return r;
}

static void socket_unwatch_fds(Socket *s) {
        SocketPort *p;

        assert(s);

        LIST_FOREACH(port, p, s->ports) {
                if (p->fd < 0)
                        continue;

                unit_unwatch_fd(UNIT(s), &p->fd_watch);
        }
}

static int socket_watch_fds(Socket *s) {
        SocketPort *p;
        int r;

        assert(s);

        LIST_FOREACH(port, p, s->ports) {
                if (p->fd < 0)
                        continue;

                if ((r = unit_watch_fd(UNIT(s), p->fd, EPOLLIN, &p->fd_watch)) < 0)
                        goto fail;
        }

        return 0;

fail:
        socket_unwatch_fds(s);
        return r;
}

static void socket_set_state(Socket *s, SocketState state) {
        SocketState old_state;
        assert(s);

        old_state = s->state;
        s->state = state;

        if (state != SOCKET_START_PRE &&
            state != SOCKET_START_POST &&
            state != SOCKET_STOP_PRE &&
            state != SOCKET_STOP_PRE_SIGTERM &&
            state != SOCKET_STOP_PRE_SIGKILL &&
            state != SOCKET_STOP_POST &&
            state != SOCKET_STOP_POST_SIGTERM &&
            state != SOCKET_STOP_POST_SIGKILL)
                unit_unwatch_timer(UNIT(s), &s->timer_watch);

        if (state != SOCKET_START_PRE &&
            state != SOCKET_START_POST &&
            state != SOCKET_STOP_PRE &&
            state != SOCKET_STOP_PRE_SIGTERM &&
            state != SOCKET_STOP_PRE_SIGKILL &&
            state != SOCKET_STOP_POST &&
            state != SOCKET_STOP_POST_SIGTERM &&
            state != SOCKET_STOP_POST_SIGKILL)
                if (s->control_pid > 0) {
                        unit_unwatch_pid(UNIT(s), s->control_pid);
                        s->control_pid = 0;
                }

        if (state != SOCKET_START_PRE &&
            state != SOCKET_START_POST &&
            state != SOCKET_STOP_PRE &&
            state != SOCKET_STOP_POST)
                s->control_command = NULL;

        if (state != SOCKET_START_POST &&
            state != SOCKET_LISTENING &&
            state != SOCKET_RUNNING &&
            state != SOCKET_STOP_PRE &&
            state != SOCKET_STOP_PRE_SIGTERM &&
            state != SOCKET_STOP_PRE_SIGKILL)
                socket_close_fds(s);

        if (state != SOCKET_LISTENING)
                socket_unwatch_fds(s);

        log_debug("%s changed %s → %s", unit_id(UNIT(s)), state_string_table[old_state], state_string_table[state]);

        unit_notify(UNIT(s), state_translation_table[old_state], state_translation_table[state]);
}

static int socket_spawn(Socket *s, ExecCommand *c, bool timeout, pid_t *_pid) {
        pid_t pid;
        int r;

        assert(s);
        assert(c);
        assert(_pid);

        if (timeout) {
                if ((r = unit_watch_timer(UNIT(s), s->timeout_usec, &s->timer_watch)) < 0)
                        goto fail;
        } else
                unit_unwatch_timer(UNIT(s), &s->timer_watch);

        if ((r = exec_spawn(c, &s->exec_context, NULL, 0, &pid)) < 0)
                goto fail;

        if ((r = unit_watch_pid(UNIT(s), pid)) < 0)
                /* FIXME: we need to do something here */
                goto fail;

        *_pid = pid;

        return 0;

fail:
        if (timeout)
                unit_unwatch_timer(UNIT(s), &s->timer_watch);

        return r;
}

static void socket_enter_dead(Socket *s, bool success) {
        assert(s);

        if (!success)
                s->failure = true;

        socket_set_state(s, s->failure ? SOCKET_MAINTAINANCE : SOCKET_DEAD);
}

static void socket_enter_stop_post(Socket *s, bool success) {
        int r;
        assert(s);

        if (!success)
                s->failure = true;

        if ((s->control_command = s->exec_command[SOCKET_EXEC_STOP_POST]))
                if ((r = socket_spawn(s, s->control_command, true, &s->control_pid)) < 0)
                        goto fail;

        socket_set_state(s, SOCKET_STOP_POST);

        if (!s->control_command)
                socket_enter_dead(s, true);

        return;

fail:
        log_warning("%s failed to run stop-post executable: %s", unit_id(UNIT(s)), strerror(-r));
        socket_enter_dead(s, false);
}

static void socket_enter_signal(Socket *s, SocketState state, bool success) {
        int r;

        assert(s);

        if (!success)
                s->failure = true;

        if (s->control_pid > 0) {
                int sig;

                sig = (state == SOCKET_STOP_PRE_SIGTERM || state == SOCKET_STOP_POST_SIGTERM) ? SIGTERM : SIGKILL;

                if (kill(s->control_pid, sig) < 0 && errno != ESRCH) {
                        r = -errno;
                        goto fail;
                }
        }

        socket_set_state(s, state);

        if (s->control_pid <= 0)
                socket_enter_dead(s, true);

        return;

fail:
        log_warning("%s failed to kill processes: %s", unit_id(UNIT(s)), strerror(-r));

        if (state == SOCKET_STOP_PRE_SIGTERM || state == SOCKET_STOP_PRE_SIGKILL)
                socket_enter_stop_post(s, false);
        else
                socket_enter_dead(s, false);
}

static void socket_enter_stop_pre(Socket *s, bool success) {
        int r;
        assert(s);

        if (!success)
                s->failure = true;

        if ((s->control_command = s->exec_command[SOCKET_EXEC_STOP_PRE]))
                if ((r = socket_spawn(s, s->control_command, true, &s->control_pid)) < 0)
                        goto fail;

        socket_set_state(s, SOCKET_STOP_PRE);

        if (!s->control_command)
                socket_enter_stop_post(s, true);

        return;

fail:
        log_warning("%s failed to run stop-pre executable: %s", unit_id(UNIT(s)), strerror(-r));
        socket_enter_stop_post(s, false);
}

static void socket_enter_listening(Socket *s) {
        int r;
        assert(s);

        if ((r = socket_watch_fds(s)) < 0) {
                log_warning("%s failed to watch sockets: %s", unit_id(UNIT(s)), strerror(-r));
                goto fail;
        }

        socket_set_state(s, SOCKET_LISTENING);
        return;

fail:
        socket_enter_stop_pre(s, false);
}

static void socket_enter_start_post(Socket *s) {
        int r;
        assert(s);

        if ((r = socket_open_fds(s)) < 0) {
                log_warning("%s failed to listen on sockets: %s", unit_id(UNIT(s)), strerror(-r));
                goto fail;
        }

        if ((s->control_command = s->exec_command[SOCKET_EXEC_START_POST]))
                if ((r = socket_spawn(s, s->control_command, true, &s->control_pid)) < 0) {
                        log_warning("%s failed to run start-post executable: %s", unit_id(UNIT(s)), strerror(-r));
                        goto fail;
                }

        socket_set_state(s, SOCKET_START_POST);

        if (!s->control_command)
                socket_enter_listening(s);

        return;

fail:
        socket_enter_stop_pre(s, false);
}

static void socket_enter_start_pre(Socket *s) {
        int r;
        assert(s);

        if ((s->control_command = s->exec_command[SOCKET_EXEC_START_PRE]))
                if ((r = socket_spawn(s, s->control_command, true, &s->control_pid)) < 0)
                        goto fail;

        socket_set_state(s, SOCKET_START_PRE);

        if (!s->control_command)
                socket_enter_start_post(s);

        return;

fail:
        log_warning("%s failed to run start-pre exectuable: %s", unit_id(UNIT(s)), strerror(-r));
        socket_enter_dead(s, false);
}

static void socket_enter_running(Socket *s) {
        int r;

        assert(s);

        if ((r = manager_add_job(UNIT(s)->meta.manager, JOB_START, UNIT(s->service), JOB_REPLACE, true, NULL)) < 0)
                goto fail;

        socket_set_state(s, SOCKET_RUNNING);
        return;

fail:
        log_warning("%s failed to queue socket startup job: %s", unit_id(UNIT(s)), strerror(-r));
        socket_enter_dead(s, false);
}

static void socket_run_next(Socket *s, bool success) {
        int r;

        assert(s);
        assert(s->control_command);
        assert(s->control_command->command_next);

        if (!success)
                s->failure = true;

        s->control_command = s->control_command->command_next;

        if ((r = socket_spawn(s, s->control_command, true, &s->control_pid)) < 0)
                goto fail;

        return;

fail:
        if (s->state == SOCKET_STOP_PRE)
                socket_enter_stop_post(s, false);
        else if (s->state == SOCKET_STOP_POST)
                socket_enter_dead(s, false);
        else
                socket_enter_stop_pre(s, false);
}

static int socket_start(Unit *u) {
        Socket *s = SOCKET(u);

        assert(s);

        /* We cannot fulfill this request right now, try again later
         * please! */
        if (s->state == SOCKET_STOP_PRE ||
            s->state == SOCKET_STOP_PRE_SIGKILL ||
            s->state == SOCKET_STOP_PRE_SIGTERM ||
            s->state == SOCKET_STOP_POST ||
            s->state == SOCKET_STOP_POST_SIGTERM ||
            s->state == SOCKET_STOP_POST_SIGKILL)
                return -EAGAIN;

        if (s->state == SOCKET_START_PRE ||
            s->state == SOCKET_START_POST)
                return 0;

        /* Cannot run this without the service being around */
        if (s->service->meta.load_state != UNIT_LOADED)
                return -ENOENT;

        assert(s->state == SOCKET_DEAD || s->state == SOCKET_MAINTAINANCE);

        s->failure = false;
        socket_enter_start_pre(s);
        return 0;
}

static int socket_stop(Unit *u) {
        Socket *s = SOCKET(u);

        assert(s);

        /* We cannot fulfill this request right now, try again later
         * please! */
        if (s->state == SOCKET_START_PRE ||
            s->state == SOCKET_START_POST)
                return -EAGAIN;

        assert(s->state == SOCKET_LISTENING || s->state == SOCKET_RUNNING);

        socket_enter_stop_pre(s, true);
        return 0;
}

static UnitActiveState socket_active_state(Unit *u) {
        assert(u);

        return state_translation_table[SOCKET(u)->state];
}

static void socket_fd_event(Unit *u, int fd, uint32_t events, Watch *w) {
        Socket *s = SOCKET(u);

        assert(s);

        log_debug("Incoming traffic on %s", unit_id(u));

        if (events != EPOLLIN)
                socket_enter_stop_pre(s, false);

        socket_enter_running(s);
}

static void socket_sigchld_event(Unit *u, pid_t pid, int code, int status) {
        Socket *s = SOCKET(u);
        bool success;

        assert(s);
        assert(pid >= 0);

        success = code == CLD_EXITED && status == 0;
        s->failure = s->failure || !success;

        assert(s->control_pid == pid);
        assert(s->control_command);

        exec_status_fill(&s->control_command->exec_status, pid, code, status);
        s->control_pid = 0;

        log_debug("%s control process exited, code=%s status=%i", unit_id(u), sigchld_code_to_string(code), status);

        if (s->control_command->command_next &&
            (success || (s->state == SOCKET_EXEC_STOP_PRE || s->state == SOCKET_EXEC_STOP_POST))) {
                log_debug("%s running next command for the state %s", unit_id(u), state_string_table[s->state]);
                socket_run_next(s, success);
        } else {
                /* No further commands for this step, so let's figure
                 * out what to do next */

                log_debug("%s got final SIGCHLD for state %s", unit_id(u), state_string_table[s->state]);

                switch (s->state) {

                case SOCKET_START_PRE:
                        if (success)
                                socket_enter_start_post(s);
                        else
                                socket_enter_stop_pre(s, false);
                        break;

                case SOCKET_START_POST:
                        if (success)
                                socket_enter_listening(s);
                        else
                                socket_enter_stop_pre(s, false);
                        break;

                case SOCKET_STOP_PRE:
                case SOCKET_STOP_PRE_SIGTERM:
                case SOCKET_STOP_PRE_SIGKILL:
                        socket_enter_stop_post(s, success);
                        break;

                case SOCKET_STOP_POST:
                case SOCKET_STOP_POST_SIGTERM:
                case SOCKET_STOP_POST_SIGKILL:
                        socket_enter_dead(s, success);
                        break;

                default:
                        assert_not_reached("Uh, control process died at wrong time.");
                }
        }
}

static void socket_timer_event(Unit *u, uint64_t elapsed, Watch *w) {
        Socket *s = SOCKET(u);

        assert(s);
        assert(elapsed == 1);

        assert(w == &s->timer_watch);

        switch (s->state) {

        case SOCKET_START_PRE:
        case SOCKET_START_POST:
                log_warning("%s operation timed out. Stopping.", unit_id(u));
                socket_enter_stop_pre(s, false);
                break;

        case SOCKET_STOP_PRE:
                log_warning("%s stopping timed out. Terminating.", unit_id(u));
                socket_enter_signal(s, SOCKET_STOP_PRE_SIGTERM, false);
                break;

        case SOCKET_STOP_PRE_SIGTERM:
                log_warning("%s stopping timed out. Killing.", unit_id(u));
                socket_enter_signal(s, SOCKET_STOP_PRE_SIGKILL, false);
                break;

        case SOCKET_STOP_PRE_SIGKILL:
                log_warning("%s still around after SIGKILL. Ignoring.", unit_id(u));
                socket_enter_stop_post(s, false);
                break;

        case SOCKET_STOP_POST:
                log_warning("%s stopping timed out (2). Terminating.", unit_id(u));
                socket_enter_signal(s, SOCKET_STOP_POST_SIGTERM, false);
                break;

        case SOCKET_STOP_POST_SIGTERM:
                log_warning("%s stopping timed out (2). Killing.", unit_id(u));
                socket_enter_signal(s, SOCKET_STOP_POST_SIGKILL, false);
                break;

        case SOCKET_STOP_POST_SIGKILL:
                log_warning("%s still around after SIGKILL (2). Entering maintainance mode.", unit_id(u));
                socket_enter_dead(s, false);
                break;

        default:
                assert_not_reached("Timeout at wrong time.");
        }
}

int socket_collect_fds(Socket *s, int **fds, unsigned *n_fds) {
        int *rfds;
        unsigned rn_fds, k;
        SocketPort *p;

        assert(s);
        assert(fds);
        assert(n_fds);

        /* Called from the service code for requesting our fds */

        rn_fds = 0;
        LIST_FOREACH(port, p, s->ports)
                if (p->fd >= 0)
                        rn_fds++;

        if (!(rfds = new(int, rn_fds)) < 0)
                return -ENOMEM;

        k = 0;
        LIST_FOREACH(port, p, s->ports)
                if (p->fd >= 0)
                        rfds[k++] = p->fd;

        assert(k == rn_fds);

        *fds = rfds;
        *n_fds = rn_fds;

        return 0;
}

void socket_notify_service_dead(Socket *s) {
        assert(s);

        /* The service is dead. Dang. */

        if (s->state == SOCKET_RUNNING) {
                log_debug("%s got notified about service death.", unit_id(UNIT(s)));
                socket_enter_listening(s);
        }
}

const UnitVTable socket_vtable = {
        .suffix = ".socket",

        .init = socket_init,
        .done = socket_done,

        .dump = socket_dump,

        .start = socket_start,
        .stop = socket_stop,

        .active_state = socket_active_state,

        .fd_event = socket_fd_event,
        .sigchld_event = socket_sigchld_event,
        .timer_event = socket_timer_event
};
