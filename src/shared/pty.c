/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 David Herrmann <dh.herrmann@gmail.com>

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

/*
 * PTY
 * A PTY object represents a single PTY connection between a master and a
 * child. The child process is fork()ed so the caller controls what program
 * will be run.
 *
 * Programs like /bin/login tend to perform a vhangup() on their TTY
 * before running the login procedure. This also causes the pty master
 * to get a EPOLLHUP event as long as no client has the TTY opened.
 * This means, we cannot use the TTY connection as reliable way to track
 * the client. Instead, we _must_ rely on the PID of the client to track
 * them.
 * However, this has the side effect that if the client forks and the
 * parent exits, we loose them and restart the client. But this seems to
 * be the expected behavior so we implement it here.
 *
 * Unfortunately, epoll always polls for EPOLLHUP so as long as the
 * vhangup() is ongoing, we will _always_ get EPOLLHUP and cannot sleep.
 * This gets worse if the client closes the TTY but doesn't exit.
 * Therefore, the fd must be edge-triggered in the epoll-set so we
 * only get the events once they change.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "barrier.h"
#include "macro.h"
#include "pty.h"
#include "ring.h"
#include "util.h"

#define PTY_BUFSIZE 4096

enum {
        PTY_ROLE_UNKNOWN,
        PTY_ROLE_PARENT,
        PTY_ROLE_CHILD,
};

struct Pty {
        unsigned long ref;
        Barrier barrier;
        int fd;
        pid_t child;
        sd_event_source *fd_source;
        sd_event_source *child_source;

        char in_buf[PTY_BUFSIZE];
        Ring out_buf;

        pty_event_t event_fn;
        void *event_fn_userdata;

        bool needs_requeue : 1;
        unsigned int role : 2;
};

int pty_new(Pty **out) {
        _pty_unref_ Pty *pty = NULL;
        int r;

        assert_return(out, -EINVAL);

        pty = new0(Pty, 1);
        if (!pty)
                return -ENOMEM;

        pty->ref = 1;
        pty->fd = -1;
        pty->barrier = (Barrier) BARRIER_NULL;

        pty->fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);
        if (pty->fd < 0)
                return -errno;

        /*
         * The slave-node is initialized to uid/gid of the caller of
         * posix_openpt(). Only if devpts is mounted with fixed uid/gid this is
         * skipped. In that case, grantpt() can overwrite these, but then you
         * have to be root to use chown() (or a pt_chown helper has to be
         * present). In those cases grantpt() really does something,
         * otherwise it's a no-op. We call grantpt() here to try supporting
         * those cases, even though no-one uses that, I guess. If you need other
         * access-rights, set them yourself after this call returns (no, this is
         * not racy, it looks racy, but races regarding your own UID are never
         * important as an attacker could ptrace you; and the slave-pty is also
         * still locked).
         */
        r = grantpt(pty->fd);
        if (r < 0)
                return -errno;

        r = barrier_create(&pty->barrier);
        if (r < 0)
                return r;

        *out = pty;
        pty = NULL;
        return 0;
}

Pty *pty_ref(Pty *pty) {
        if (!pty || pty->ref < 1)
                return NULL;

        ++pty->ref;
        return pty;
}

Pty *pty_unref(Pty *pty) {
        if (!pty || pty->ref < 1 || --pty->ref > 0)
                return NULL;

        pty_close(pty);
        pty->child_source = sd_event_source_unref(pty->child_source);
        barrier_destroy(&pty->barrier);
        ring_clear(&pty->out_buf);
        free(pty);

        return NULL;
}

Barrier *pty_get_barrier(Pty *pty) {
        assert(pty);
        return &pty->barrier;
}

bool pty_is_unknown(Pty *pty) {
        return pty && pty->role == PTY_ROLE_UNKNOWN;
}

bool pty_is_parent(Pty *pty) {
        return pty && pty->role == PTY_ROLE_PARENT;
}

bool pty_is_child(Pty *pty) {
        return pty && pty->role == PTY_ROLE_CHILD;
}

bool pty_has_child(Pty *pty) {
        return pty_is_parent(pty) && pty->child > 0;
}

pid_t pty_get_child(Pty *pty) {
        return pty_has_child(pty) ? pty->child : -ECHILD;
}

bool pty_is_open(Pty *pty) {
        return pty && pty->fd >= 0;
}

int pty_get_fd(Pty *pty) {
        assert_return(pty, -EINVAL);

        return pty_is_open(pty) ? pty->fd : -EPIPE;
}

int pty_make_child(Pty *pty) {
        _cleanup_free_ char *slave_name = NULL;
        int r, fd;

        assert_return(pty, -EINVAL);
        assert_return(pty_is_unknown(pty), -EALREADY);

        r = ptsname_malloc(pty->fd, &slave_name);
        if (r < 0)
                return -errno;

        fd = open(slave_name, O_RDWR | O_CLOEXEC | O_NOCTTY);
        if (fd < 0)
                return -errno;

        safe_close(pty->fd);
        pty->fd = fd;
        pty->child = getpid();
        pty->role = PTY_ROLE_CHILD;
        barrier_set_role(&pty->barrier, BARRIER_CHILD);

        return 0;
}

int pty_make_parent(Pty *pty, pid_t child) {
        assert_return(pty, -EINVAL);
        assert_return(pty_is_unknown(pty), -EALREADY);

        pty->child = child;
        pty->role = PTY_ROLE_PARENT;

        return 0;
}

int pty_unlock(Pty *pty) {
        assert_return(pty, -EINVAL);
        assert_return(pty_is_unknown(pty) || pty_is_parent(pty), -EINVAL);
        assert_return(pty_is_open(pty), -ENODEV);

        return unlockpt(pty->fd) < 0 ? -errno : 0;
}

int pty_setup_child(Pty *pty) {
        struct termios attr;
        pid_t pid;
        int r;

        assert_return(pty, -EINVAL);
        assert_return(pty_is_child(pty), -EINVAL);
        assert_return(pty_is_open(pty), -EALREADY);

        r = sigprocmask_many(SIG_SETMASK, -1);
        if (r < 0)
                return r;

        r = reset_all_signal_handlers();
        if (r < 0)
                return r;

        pid = setsid();
        if (pid < 0 && errno != EPERM)
                return -errno;

        r = ioctl(pty->fd, TIOCSCTTY, 0);
        if (r < 0)
                return -errno;

        r = tcgetattr(pty->fd, &attr);
        if (r < 0)
                return -errno;

        /* erase character should be normal backspace, PLEASEEE! */
        attr.c_cc[VERASE] = 010;
        /* always set UTF8 flag */
        attr.c_iflag |= IUTF8;

        r = tcsetattr(pty->fd, TCSANOW, &attr);
        if (r < 0)
                return -errno;

        if (dup2(pty->fd, STDIN_FILENO) != STDIN_FILENO ||
            dup2(pty->fd, STDOUT_FILENO) != STDOUT_FILENO ||
            dup2(pty->fd, STDERR_FILENO) != STDERR_FILENO)
                return -errno;

        /* only close FD if it's not a std-fd */
        pty->fd = (pty->fd > 2) ? safe_close(pty->fd) : -1;

        return 0;
}

void pty_close(Pty *pty) {
        if (!pty_is_open(pty))
                return;

        pty->fd_source = sd_event_source_unref(pty->fd_source);
        pty->fd = safe_close(pty->fd);
}

/*
 * Drain input-queue and dispatch data via the event-handler. Returns <0 on
 * error, 0 if queue is empty and 1 if we couldn't empty the input queue fast
 * enough and there's still data left.
 */
static int pty_dispatch_read(Pty *pty) {
        unsigned int i;
        ssize_t len;
        int r;

        /*
         * We're edge-triggered, means we need to read the whole queue. This,
         * however, might cause us to stall if the writer is faster than we
         * are. Therefore, try reading as much as 8 times (32KiB) and only
         * bail out then.
         */

        for (i = 0; i < 8; ++i) {
                len = read(pty->fd, pty->in_buf, sizeof(pty->in_buf) - 1);
                if (len < 0) {
                        if (errno == EINTR)
                                continue;

                        return (errno == EAGAIN) ? 0 : -errno;
                } else if (len == 0) {
                        continue;
                }

                /* set terminating zero for debugging safety */
                pty->in_buf[len] = 0;
                r = pty->event_fn(pty, pty->event_fn_userdata, PTY_DATA, pty->in_buf, len);
                if (r < 0)
                        return r;
        }

        /* still data left, make sure we're queued again */
        pty->needs_requeue = true;

        return 1;
}

/*
 * Drain output-queue by writing data to the pty. Returns <0 on error, 0 if the
 * output queue is empty now and 1 if we couldn't empty the output queue fast
 * enough and there's still data left.
 */
static int pty_dispatch_write(Pty *pty) {
        struct iovec vec[2];
        unsigned int i;
        ssize_t len;
        size_t num;

        /*
         * Same as pty_dispatch_read(), we're edge-triggered so we need to call
         * write() until either all data is written or it returns EAGAIN. We
         * call it twice and if it still writes successfully, we reschedule.
         */

        for (i = 0; i < 2; ++i) {
                num = ring_peek(&pty->out_buf, vec);
                if (num < 1)
                        return 0;

                len = writev(pty->fd, vec, (int)num);
                if (len < 0) {
                        if (errno == EINTR)
                                continue;

                        return (errno == EAGAIN) ? 1 : -errno;
                } else if (len == 0) {
                        continue;
                }

                ring_pull(&pty->out_buf, (size_t)len);
        }

        /* still data left, make sure we're queued again */
        if (ring_get_size(&pty->out_buf) > 0) {
                pty->needs_requeue = true;
                return 1;
        }

        return 0;
}

static int pty_fd_fn(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Pty *pty = userdata;
        int r_hup = 0, r_write = 0, r_read = 0, r;

        /*
         * Whenever we encounter I/O errors, we have to make sure to drain the
         * input queue first, before we handle any HUP. A child might send us
         * a message and immediately close the queue. We must not handle the
         * HUP first or we loose data.
         * Therefore, if we read a message successfully, we always return
         * success and wait for the next event-loop iteration. Furthermore,
         * whenever there is a write-error, we must try reading from the input
         * queue even if EPOLLIN is not set. The input might have arrived in
         * between epoll_wait() and write(). Therefore, write-errors are only
         * ever handled if the input-queue is empty. In all other cases they
         * are ignored until either reading fails or the input queue is empty.
         */

        if (revents & (EPOLLHUP | EPOLLERR))
                r_hup = -EPIPE;

        if (revents & EPOLLOUT)
                r_write = pty_dispatch_write(pty);

        /* Awesome! Kernel signals HUP without IN but queues are not empty.. */
        if ((revents & EPOLLIN) || r_hup < 0 || r_write < 0) {
                r_read = pty_dispatch_read(pty);
                if (r_read > 0)
                        return 0; /* still data left to fetch next round */
        }

        if (r_hup < 0 || r_write < 0 || r_read < 0) {
                /* PTY closed and input-queue drained */
                pty_close(pty);
                r = pty->event_fn(pty, pty->event_fn_userdata, PTY_HUP, NULL, 0);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int pty_fd_prepare_fn(sd_event_source *source, void *userdata) {
        Pty *pty = userdata;
        int r;

        if (pty->needs_requeue) {
                /*
                 * We're edge-triggered. In case we couldn't handle all events
                 * or in case new write-data is queued, we set needs_requeue.
                 * Before going asleep, we set the io-events *again*. sd-event
                 * notices that we're edge-triggered and forwards the call to
                 * the kernel even if the events didn't change. The kernel will
                 * check the events and re-queue us on the ready queue in case
                 * an event is pending.
                 */
                r = sd_event_source_set_io_events(source, EPOLLHUP | EPOLLERR | EPOLLIN | EPOLLOUT | EPOLLET);
                if (r >= 0)
                        pty->needs_requeue = false;
        }

        return 0;
}

static int pty_child_fn(sd_event_source *source, const siginfo_t *si, void *userdata) {
        Pty *pty = userdata;
        int r;

        pty->child = 0;

        r = pty->event_fn(pty, pty->event_fn_userdata, PTY_CHILD, si, sizeof(*si));
        if (r < 0)
                return r;

        return 0;
}

int pty_attach_event(Pty *pty, sd_event *event, pty_event_t event_fn, void *event_fn_userdata) {
        int r;

        assert_return(pty, -EINVAL);
        assert_return(event, -EINVAL);
        assert_return(event_fn, -EINVAL);
        assert_return(pty_is_parent(pty), -EINVAL);

        pty_detach_event(pty);

        if (pty_is_open(pty)) {
                r = sd_event_add_io(event,
                                    &pty->fd_source,
                                    pty->fd,
                                    EPOLLHUP | EPOLLERR | EPOLLIN | EPOLLOUT | EPOLLET,
                                    pty_fd_fn,
                                    pty);
                if (r < 0)
                        goto error;

                r = sd_event_source_set_prepare(pty->fd_source, pty_fd_prepare_fn);
                if (r < 0)
                        goto error;
        }

        if (pty_has_child(pty)) {
                r = sd_event_add_child(event,
                                       &pty->child_source,
                                       pty->child,
                                       WEXITED,
                                       pty_child_fn,
                                       pty);
                if (r < 0)
                        goto error;
        }

        pty->event_fn = event_fn;
        pty->event_fn_userdata = event_fn_userdata;

        return 0;

error:
        pty_detach_event(pty);
        return r;
}

void pty_detach_event(Pty *pty) {
        if (!pty)
                return;

        pty->child_source = sd_event_source_unref(pty->child_source);
        pty->fd_source = sd_event_source_unref(pty->fd_source);
        pty->event_fn = NULL;
        pty->event_fn_userdata = NULL;
}

int pty_write(Pty *pty, const void *buf, size_t size) {
        bool was_empty;
        int r;

        assert_return(pty, -EINVAL);
        assert_return(pty_is_open(pty), -ENODEV);
        assert_return(pty_is_parent(pty), -ENODEV);

        if (size < 1)
                return 0;

        /*
         * Push @buf[0..@size] into the output ring-buffer. In case the
         * ring-buffer wasn't empty beforehand, we're already waiting for
         * EPOLLOUT and we're done. If it was empty, we have to re-queue the
         * FD for EPOLLOUT as we're edge-triggered and wouldn't get any new
         * EPOLLOUT event.
         */

        was_empty = ring_get_size(&pty->out_buf) < 1;

        r = ring_push(&pty->out_buf, buf, size);
        if (r < 0)
                return r;

        if (was_empty)
                pty->needs_requeue = true;

        return 0;
}

int pty_signal(Pty *pty, int sig) {
        assert_return(pty, -EINVAL);
        assert_return(pty_is_open(pty), -ENODEV);
        assert_return(pty_is_parent(pty), -ENODEV);

        return ioctl(pty->fd, TIOCSIG, sig) < 0 ? -errno : 0;
}

int pty_resize(Pty *pty, unsigned short term_width, unsigned short term_height) {
        struct winsize ws = {
                .ws_col = term_width,
                .ws_row = term_height,
        };

        assert_return(pty, -EINVAL);
        assert_return(pty_is_open(pty), -ENODEV);
        assert_return(pty_is_parent(pty), -ENODEV);

        /*
         * This will send SIGWINCH to the pty slave foreground process group.
         * We will also get one, but we don't need it.
         */
        return ioctl(pty->fd, TIOCSWINSZ, &ws) < 0 ? -errno : 0;
}

pid_t pty_fork(Pty **out, sd_event *event, pty_event_t event_fn, void *event_fn_userdata, unsigned short initial_term_width, unsigned short initial_term_height) {
        _pty_unref_ Pty *pty = NULL;
        int r;
        pid_t pid;

        assert_return(out, -EINVAL);
        assert_return((event && event_fn) || (!event && !event_fn), -EINVAL);

        r = pty_new(&pty);
        if (r < 0)
                return r;

        r = pty_unlock(pty);
        if (r < 0)
                return r;

        pid = fork();
        if (pid < 0)
                return -errno;

        if (pid == 0) {
                /* child */

                r = pty_make_child(pty);
                if (r < 0)
                        _exit(-r);

                r = pty_setup_child(pty);
                if (r < 0)
                        _exit(-r);

                /* sync with parent */
                if (!barrier_place_and_sync(&pty->barrier))
                        _exit(1);

                /* fallthrough and return the child's PTY object */
        } else {
                /* parent */

                r = pty_make_parent(pty, pid);
                if (r < 0)
                        goto parent_error;

                r = pty_resize(pty, initial_term_width, initial_term_height);
                if (r < 0)
                        goto parent_error;

                if (event) {
                        r = pty_attach_event(pty, event, event_fn, event_fn_userdata);
                        if (r < 0)
                                goto parent_error;
                }

                /* sync with child */
                if (!barrier_place_and_sync(&pty->barrier)) {
                        r = -ECHILD;
                        goto parent_error;
                }

                /* fallthrough and return the parent's PTY object */
        }

        *out = pty;
        pty = NULL;
        return pid;

parent_error:
        barrier_abort(&pty->barrier);
        waitpid(pty->child, NULL, 0);
        pty->child = 0;
        return r;
}
