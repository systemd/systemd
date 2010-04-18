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
#include <arpa/inet.h>

#include "unit.h"
#include "socket.h"
#include "log.h"
#include "load-dropin.h"
#include "load-fragment.h"
#include "strv.h"
#include "unit-name.h"
#include "dbus-socket.h"

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
        [SOCKET_FINAL_SIGTERM] = UNIT_DEACTIVATING,
        [SOCKET_FINAL_SIGKILL] = UNIT_DEACTIVATING,
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
        [SOCKET_FINAL_SIGTERM] = "final-sigterm",
        [SOCKET_FINAL_SIGKILL] = "final-sigkill",
        [SOCKET_MAINTAINANCE] = "maintainance"
};

static void socket_unwatch_control_pid(Socket *s) {
        assert(s);

        if (s->control_pid <= 0)
                return;

        unit_unwatch_pid(UNIT(s), s->control_pid);
        s->control_pid = 0;
}

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
        exec_command_free_array(s->exec_command, _SOCKET_EXEC_COMMAND_MAX);
        s->control_command = NULL;

        socket_unwatch_control_pid(s);

        s->service = NULL;

        free(s->bind_to_device);
        s->bind_to_device = NULL;

        unit_unwatch_timer(u, &s->timer_watch);
}

static void socket_init(Unit *u) {
        Socket *s = SOCKET(u);

        assert(u);
        assert(u->meta.load_state == UNIT_STUB);

        s->timer_watch.type = WATCH_INVALID;
        s->backlog = SOMAXCONN;
        s->timeout_usec = DEFAULT_TIMEOUT_USEC;
        s->directory_mode = 0755;
        s->socket_mode = 0666;

        exec_context_init(&s->exec_context);
}

static bool have_non_accept_socket(Socket *s) {
        SocketPort *p;

        assert(s);

        if (!s->accept)
                return true;

        LIST_FOREACH(port, p, s->ports)
                if (!socket_address_can_accept(&p->address))
                        return true;

        return false;
}

static int socket_verify(Socket *s) {
        assert(s);

        if (UNIT(s)->meta.load_state != UNIT_LOADED)
                return 0;

        if (!s->ports) {
                log_error("%s lacks Listen setting. Refusing.", UNIT(s)->meta.id);
                return -EINVAL;
        }

        return 0;
}

static int socket_load(Unit *u) {
        Socket *s = SOCKET(u);
        int r;

        assert(u);
        assert(u->meta.load_state == UNIT_STUB);

        if ((r = unit_load_fragment_and_dropin(u)) < 0)
                return r;

        /* This is a new unit? Then let's add in some extras */
        if (u->meta.load_state == UNIT_LOADED) {

                if (have_non_accept_socket(s)) {
                        if ((r = unit_load_related_unit(u, ".service", (Unit**) &s->service)))
                                return r;

                        if ((r = unit_add_dependency(u, UNIT_BEFORE, UNIT(s->service))) < 0)
                                return r;
                }

                if ((r = unit_add_exec_dependencies(u, &s->exec_context)) < 0)
                        return r;

                if ((r = unit_add_default_cgroup(u)) < 0)
                        return r;
        }

        return socket_verify(s);
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

        static const char* const command_table[_SOCKET_EXEC_COMMAND_MAX] = {
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
                "%sBacklog: %u\n"
                "%sKillMode: %s\n"
                "%sSocketMode: %04o\n"
                "%sDirectoryMode: %04o\n",
                prefix, state_string_table[s->state],
                prefix, yes_no(s->bind_ipv6_only),
                prefix, s->backlog,
                prefix, kill_mode_to_string(s->kill_mode),
                prefix, s->socket_mode,
                prefix, s->directory_mode);

        if (s->control_pid > 0)
                fprintf(f,
                        "%sControl PID: %llu\n",
                        prefix, (unsigned long long) s->control_pid);

        if (s->bind_to_device)
                fprintf(f,
                        "%sBindToDevice: %s\n",
                        prefix, s->bind_to_device);

        if (s->accept)
                fprintf(f,
                        "%sAccepted: %u\n",
                        prefix, s->n_accepted);

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

        for (c = 0; c < _SOCKET_EXEC_COMMAND_MAX; c++) {
                if (!s->exec_command[c])
                        continue;

                fprintf(f, "%s→ %s:\n",
                        prefix, command_table[c]);

                exec_command_dump_list(s->exec_command[c], f, prefix2);
        }

        free(p2);
}

static int instance_from_socket(int fd, unsigned nr, char **instance) {
        socklen_t l;
        char *r;
        union {
                struct sockaddr sa;
                struct sockaddr_un un;
                struct sockaddr_in in;
                struct sockaddr_in6 in6;
                struct sockaddr_storage storage;
        } local, remote;

        assert(fd >= 0);
        assert(instance);

        l = sizeof(local);
        if (getsockname(fd, &local.sa, &l) < 0)
                return -errno;

        l = sizeof(remote);
        if (getpeername(fd, &remote.sa, &l) < 0)
                return -errno;

        switch (local.sa.sa_family) {

        case AF_INET: {
                uint32_t
                        a = ntohl(local.in.sin_addr.s_addr),
                        b = ntohl(remote.in.sin_addr.s_addr);

                if (asprintf(&r,
                             "%u-%u.%u.%u.%u-%u-%u.%u.%u.%u-%u",
                             nr,
                             a >> 24, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF,
                             ntohs(local.in.sin_port),
                             b >> 24, (b >> 16) & 0xFF, (b >> 8) & 0xFF, b & 0xFF,
                             ntohs(remote.in.sin_port)) < 0)
                        return -ENOMEM;

                break;
        }

        case AF_INET6: {
                char a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];

                if (asprintf(&r,
                             "%u-%s-%u-%s-%u",
                             nr,
                             inet_ntop(AF_INET6, &local.in6.sin6_addr, a, sizeof(a)),
                             ntohs(local.in6.sin6_port),
                             inet_ntop(AF_INET6, &remote.in6.sin6_addr, b, sizeof(b)),
                             ntohs(remote.in6.sin6_port)) < 0)
                        return -ENOMEM;

                break;
        }

        case AF_UNIX: {
                struct ucred ucred;

                l = sizeof(ucred);
                if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &l) < 0)
                        return -errno;

                if (asprintf(&r,
                             "%u-%llu-%llu",
                             nr,
                             (unsigned long long) ucred.pid,
                             (unsigned long long) ucred.uid) < 0)
                        return -ENOMEM;

                break;
        }

        default:
                assert_not_reached("Unhandled socket type.");
        }

        *instance = r;
        return 0;
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

                        if ((r = socket_address_listen(
                                             &p->address,
                                             s->backlog,
                                             s->bind_ipv6_only,
                                             s->bind_to_device,
                                             s->directory_mode,
                                             s->socket_mode,
                                             &p->fd)) < 0)
                                goto rollback;

                } else {
                        struct stat st;
                        assert(p->type == SOCKET_FIFO);

                        mkdir_parents(p->path, s->directory_mode);

                        if (mkfifo(p->path, s->socket_mode) < 0 && errno != EEXIST) {
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

                p->fd_watch.data.socket_accept =
                        s->accept &&
                        socket_address_can_accept(&p->address);

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
            state != SOCKET_FINAL_SIGTERM &&
            state != SOCKET_FINAL_SIGKILL) {
                unit_unwatch_timer(UNIT(s), &s->timer_watch);
                socket_unwatch_control_pid(s);
                s->control_command = NULL;
        }

        if (state != SOCKET_START_POST &&
            state != SOCKET_LISTENING &&
            state != SOCKET_RUNNING &&
            state != SOCKET_STOP_PRE &&
            state != SOCKET_STOP_PRE_SIGTERM &&
            state != SOCKET_STOP_PRE_SIGKILL)
                socket_close_fds(s);

        if (state != SOCKET_LISTENING)
                socket_unwatch_fds(s);

        if (state != old_state)
                log_debug("%s changed %s → %s", s->meta.id, state_string_table[old_state], state_string_table[state]);

        unit_notify(UNIT(s), state_translation_table[old_state], state_translation_table[state]);
}

static int socket_spawn(Socket *s, ExecCommand *c, pid_t *_pid) {
        pid_t pid;
        int r;
        char **argv;

        assert(s);
        assert(c);
        assert(_pid);

        if ((r = unit_watch_timer(UNIT(s), s->timeout_usec, &s->timer_watch)) < 0)
                goto fail;

        if (!(argv = unit_full_printf_strv(UNIT(s), c->argv))) {
                r = -ENOMEM;
                goto fail;
        }

        r = exec_spawn(c,
                       argv,
                       &s->exec_context,
                       NULL, 0,
                       true,
                       true,
                       UNIT(s)->meta.manager->confirm_spawn,
                       UNIT(s)->meta.cgroup_bondings,
                       &pid);

        strv_free(argv);
        if (r < 0)
                goto fail;

        if ((r = unit_watch_pid(UNIT(s), pid)) < 0)
                /* FIXME: we need to do something here */
                goto fail;

        *_pid = pid;

        return 0;

fail:
        unit_unwatch_timer(UNIT(s), &s->timer_watch);

        return r;
}

static void socket_enter_dead(Socket *s, bool success) {
        assert(s);

        if (!success)
                s->failure = true;

        socket_set_state(s, s->failure ? SOCKET_MAINTAINANCE : SOCKET_DEAD);
}

static void socket_enter_signal(Socket *s, SocketState state, bool success);

static void socket_enter_stop_post(Socket *s, bool success) {
        int r;
        assert(s);

        if (!success)
                s->failure = true;

        socket_unwatch_control_pid(s);

        if ((s->control_command = s->exec_command[SOCKET_EXEC_STOP_POST])) {
                if ((r = socket_spawn(s, s->control_command, &s->control_pid)) < 0)
                        goto fail;

                socket_set_state(s, SOCKET_STOP_POST);
        } else
                socket_enter_signal(s, SOCKET_FINAL_SIGTERM, true);

        return;

fail:
        log_warning("%s failed to run stop-post executable: %s", s->meta.id, strerror(-r));
        socket_enter_signal(s, SOCKET_FINAL_SIGTERM, false);
}

static void socket_enter_signal(Socket *s, SocketState state, bool success) {
        int r;
        bool sent = false;

        assert(s);

        if (!success)
                s->failure = true;

        if (s->kill_mode != KILL_NONE) {
                int sig = (state == SOCKET_STOP_PRE_SIGTERM || state == SOCKET_FINAL_SIGTERM) ? SIGTERM : SIGKILL;

                if (s->kill_mode == KILL_CONTROL_GROUP) {

                        if ((r = cgroup_bonding_kill_list(UNIT(s)->meta.cgroup_bondings, sig)) < 0) {
                                if (r != -EAGAIN && r != -ESRCH)
                                        goto fail;
                        } else
                                sent = true;
                }

                if (!sent && s->control_pid > 0)
                        if (kill(s->kill_mode == KILL_PROCESS ? s->control_pid : -s->control_pid, sig) < 0 && errno != ESRCH) {
                                r = -errno;
                                goto fail;
                        }
        }

        if (sent) {
                if ((r = unit_watch_timer(UNIT(s), s->timeout_usec, &s->timer_watch)) < 0)
                        goto fail;

                socket_set_state(s, state);
        } else if (state == SOCKET_STOP_PRE_SIGTERM || state == SOCKET_STOP_PRE_SIGKILL)
                socket_enter_stop_post(s, true);
        else
                socket_enter_dead(s, true);

        return;

fail:
        log_warning("%s failed to kill processes: %s", s->meta.id, strerror(-r));

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

        socket_unwatch_control_pid(s);

        if ((s->control_command = s->exec_command[SOCKET_EXEC_STOP_PRE])) {
                if ((r = socket_spawn(s, s->control_command, &s->control_pid)) < 0)
                        goto fail;

                socket_set_state(s, SOCKET_STOP_PRE);
        } else
                socket_enter_stop_post(s, true);

        return;

fail:
        log_warning("%s failed to run stop-pre executable: %s", s->meta.id, strerror(-r));
        socket_enter_stop_post(s, false);
}

static void socket_enter_listening(Socket *s) {
        int r;
        assert(s);

        if ((r = socket_watch_fds(s)) < 0) {
                log_warning("%s failed to watch sockets: %s", s->meta.id, strerror(-r));
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
                log_warning("%s failed to listen on sockets: %s", s->meta.id, strerror(-r));
                goto fail;
        }

        socket_unwatch_control_pid(s);

        if ((s->control_command = s->exec_command[SOCKET_EXEC_START_POST])) {
                if ((r = socket_spawn(s, s->control_command, &s->control_pid)) < 0) {
                        log_warning("%s failed to run start-post executable: %s", s->meta.id, strerror(-r));
                        goto fail;
                }

                socket_set_state(s, SOCKET_START_POST);
        } else
                socket_enter_listening(s);

        return;

fail:
        socket_enter_stop_pre(s, false);
}

static void socket_enter_start_pre(Socket *s) {
        int r;
        assert(s);

        socket_unwatch_control_pid(s);

        if ((s->control_command = s->exec_command[SOCKET_EXEC_START_PRE])) {
                if ((r = socket_spawn(s, s->control_command, &s->control_pid)) < 0)
                        goto fail;

                socket_set_state(s, SOCKET_START_PRE);
        } else
                socket_enter_start_post(s);

        return;

fail:
        log_warning("%s failed to run start-pre exectuable: %s", s->meta.id, strerror(-r));
        socket_enter_dead(s, false);
}

static void socket_enter_running(Socket *s, int cfd) {
        int r;

        assert(s);

        if (cfd < 0) {
                if ((r = manager_add_job(UNIT(s)->meta.manager, JOB_START, UNIT(s->service), JOB_REPLACE, true, NULL)) < 0)
                        goto fail;

                socket_set_state(s, SOCKET_RUNNING);
        } else {
                Unit *u;
                char *prefix, *instance, *name;

                if ((r = instance_from_socket(cfd, s->n_accepted++, &instance)))
                        goto fail;

                if (!(prefix = unit_name_to_prefix(UNIT(s)->meta.id))) {
                        free(instance);
                        r = -ENOMEM;
                        goto fail;
                }

                name = unit_name_build(prefix, instance, ".service");
                free(prefix);
                free(instance);

                if (!name)
                        r = -ENOMEM;

                r = manager_load_unit(UNIT(s)->meta.manager, name, NULL, &u);
                free(name);

                if (r < 0)
                        goto fail;

                if ((r = service_set_socket_fd(SERVICE(u), cfd) < 0))
                        goto fail;

                cfd = -1;

                if ((r = manager_add_job(u->meta.manager, JOB_START, u, JOB_REPLACE, true, NULL)) < 0)
                        goto fail;
        }

        return;

fail:
        log_warning("%s failed to queue socket startup job: %s", s->meta.id, strerror(-r));
        socket_enter_stop_pre(s, false);

        if (cfd >= 0)
                close_nointr_nofail(cfd);
}

static void socket_run_next(Socket *s, bool success) {
        int r;

        assert(s);
        assert(s->control_command);
        assert(s->control_command->command_next);

        if (!success)
                s->failure = true;

        socket_unwatch_control_pid(s);

        s->control_command = s->control_command->command_next;

        if ((r = socket_spawn(s, s->control_command, &s->control_pid)) < 0)
                goto fail;

        return;

fail:
        log_warning("%s failed to run spawn next executable: %s", s->meta.id, strerror(-r));

        if (s->state == SOCKET_START_POST)
                socket_enter_stop_pre(s, false);
        else if (s->state == SOCKET_STOP_POST)
                socket_enter_dead(s, false);
        else
                socket_enter_signal(s, SOCKET_FINAL_SIGTERM, false);
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
            s->state == SOCKET_FINAL_SIGTERM ||
            s->state == SOCKET_FINAL_SIGKILL)
                return -EAGAIN;

        if (s->state == SOCKET_START_PRE ||
            s->state == SOCKET_START_POST)
                return 0;

        /* Cannot run this without the service being around */
        if (s->service) {
                if (s->service->meta.load_state != UNIT_LOADED)
                        return -ENOENT;

                /* If the service is alredy actvie we cannot start the
                 * socket */
                if (s->service->state != SERVICE_DEAD &&
                    s->service->state != SERVICE_MAINTAINANCE &&
                    s->service->state != SERVICE_AUTO_RESTART)
                        return -EBUSY;
        }

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

        /* Already on it */
        if (s->state == SOCKET_STOP_PRE ||
            s->state == SOCKET_STOP_PRE_SIGTERM ||
            s->state == SOCKET_STOP_PRE_SIGKILL ||
            s->state == SOCKET_STOP_POST ||
            s->state == SOCKET_FINAL_SIGTERM ||
            s->state == SOCKET_FINAL_SIGTERM)
                return 0;

        assert(s->state == SOCKET_LISTENING || s->state == SOCKET_RUNNING);

        socket_enter_stop_pre(s, true);
        return 0;
}

static UnitActiveState socket_active_state(Unit *u) {
        assert(u);

        return state_translation_table[SOCKET(u)->state];
}

static const char *socket_sub_state_to_string(Unit *u) {
        assert(u);

        return state_string_table[SOCKET(u)->state];
}

static void socket_fd_event(Unit *u, int fd, uint32_t events, Watch *w) {
        Socket *s = SOCKET(u);
        int cfd = -1;

        assert(s);
        assert(fd >= 0);

        log_debug("Incoming traffic on %s", u->meta.id);

        if (events != EPOLLIN) {
                log_error("Got invalid poll event on socket.");
                goto fail;
        }

        if (w->data.socket_accept) {
                for (;;) {

                        if ((cfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK)) < 0) {

                                if (errno == EINTR)
                                        continue;

                                log_error("Failed to accept socket: %m");
                                goto fail;
                        }

                        break;
                }
        }

        socket_enter_running(s, cfd);
        return;

fail:
        socket_enter_stop_pre(s, false);
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

        log_debug("%s control process exited, code=%s status=%i", u->meta.id, sigchld_code_to_string(code), status);

        if (s->control_command->command_next && success) {
                log_debug("%s running next command for state %s", u->meta.id, state_string_table[s->state]);
                socket_run_next(s, success);
        } else {
                /* No further commands for this step, so let's figure
                 * out what to do next */

                log_debug("%s got final SIGCHLD for state %s", u->meta.id, state_string_table[s->state]);

                switch (s->state) {

                case SOCKET_START_PRE:
                        if (success)
                                socket_enter_start_post(s);
                        else
                                socket_enter_signal(s, SOCKET_FINAL_SIGTERM, false);
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
                case SOCKET_FINAL_SIGTERM:
                case SOCKET_FINAL_SIGKILL:
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
                log_warning("%s starting timed out. Terminating.", u->meta.id);
                socket_enter_signal(s, SOCKET_FINAL_SIGTERM, false);

        case SOCKET_START_POST:
                log_warning("%s starting timed out. Stopping.", u->meta.id);
                socket_enter_stop_pre(s, false);
                break;

        case SOCKET_STOP_PRE:
                log_warning("%s stopping timed out. Terminating.", u->meta.id);
                socket_enter_signal(s, SOCKET_STOP_PRE_SIGTERM, false);
                break;

        case SOCKET_STOP_PRE_SIGTERM:
                log_warning("%s stopping timed out. Killing.", u->meta.id);
                socket_enter_signal(s, SOCKET_STOP_PRE_SIGKILL, false);
                break;

        case SOCKET_STOP_PRE_SIGKILL:
                log_warning("%s still around after SIGKILL. Ignoring.", u->meta.id);
                socket_enter_stop_post(s, false);
                break;

        case SOCKET_STOP_POST:
                log_warning("%s stopping timed out (2). Terminating.", u->meta.id);
                socket_enter_signal(s, SOCKET_FINAL_SIGTERM, false);
                break;

        case SOCKET_FINAL_SIGTERM:
                log_warning("%s stopping timed out (2). Killing.", u->meta.id);
                socket_enter_signal(s, SOCKET_FINAL_SIGKILL, false);
                break;

        case SOCKET_FINAL_SIGKILL:
                log_warning("%s still around after SIGKILL (2). Entering maintainance mode.", u->meta.id);
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
                log_debug("%s got notified about service death.", s->meta.id);
                socket_enter_listening(s);
        }
}

const UnitVTable socket_vtable = {
        .suffix = ".socket",

        .init = socket_init,
        .load = socket_load,
        .done = socket_done,

        .dump = socket_dump,

        .start = socket_start,
        .stop = socket_stop,

        .active_state = socket_active_state,
        .sub_state_to_string = socket_sub_state_to_string,

        .fd_event = socket_fd_event,
        .sigchld_event = socket_sigchld_event,
        .timer_event = socket_timer_event,

        .bus_message_handler = bus_socket_message_handler
};
