/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Djalal Harouni

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

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>

#include "eventfd-util.h"
#include "util.h"


/*
 * Use this to create processes that need to setup a full context
 * and sync it with their parents using cheap mechanisms.
 *
 * This will create two blocking eventfd(s). A pair for the parent and
 * the other for the child so they can be used as a notify mechanism.
 * Each process will gets its copy of the parent and child eventfds.
 *
 * This is useful in case:
 * 1) If the parent fails or dies, the child must die.
 * 2) Child will install PR_SET_PDEATHSIG as soon as possible.
 * 3) Parent and child need to sync using less resources.
 * 4) If parent is not able to install a SIGCHLD handler:
 *    parent will wait using a blocking eventfd_read() or
 *    eventfd_child_succeeded() call on the child eventfd.
 *
 *    * If the child setup succeeded, child should notify with an
 *      EVENTFD_CHILD_SUCCEEDED, parent will continue.
 *    * If the child setup failed, child should notify with an
 *      EVENTFD_CHILD_FAILED before any _exit(). This avoids blocking
 *      the parent.
 *
 * 5) If parent is able to install a SIGCHLD handler:
 *    An empty signal handler without SA_RESTART will do it, since the
 *    blocking eventfd_read() or eventfd_parent_succeeded() of the
 *    parent will be interrupted by SIGCHLD and the call will fail with
 *    EINTR. This is useful in case the child dies abnormaly and did
 *    not have a chance to notify its parent using EVENTFD_CHILD_FAILED.
 *
 * 6) Call wait*() in the main instead of the signal handler in order
 *    to: 1) reduce side effects and 2) have a better handling for
 *    child termination in order to reduce various race conditions.
 *
 *
 * The return value of clone_with_eventfd() is the same of clone().
 * On success the eventfds[] will contain the two eventfd(s). These
 * file descriptors can be closed later with safe_close(). On failure,
 * a negative value is returned in the caller's context, and errno will
 * be set appropriately.
 *
 * Extra preliminary work:
 * 1) Child can wait before starting its setup by using the
 *    eventfd_recv_start() call on the parent eventfd, in that case the
 *    parent must notify with EVENTFD_START, after doing any preliminary
 *    work.
 *
 * Note: this function depends on systemd internal functions
 * safe_close() and it should be used only by direct binaries, no
 * libraries.
 */
pid_t clone_with_eventfd(int flags, int eventfds[2]) {
        pid_t pid;

        assert(eventfds);

        eventfds[0] = eventfd(EVENTFD_INIT, EFD_CLOEXEC);
        if (eventfds[0] < 0)
                return -1;

        eventfds[1] = eventfd(EVENTFD_INIT, EFD_CLOEXEC);
        if (eventfds[1] < 0)
                goto err_eventfd0;

        pid = syscall(__NR_clone, flags, NULL);
        if (pid < 0)
                goto err_eventfd1;

        return pid;

err_eventfd1:
        eventfds[1] = safe_close(eventfds[1]);
err_eventfd0:
        eventfds[0] = safe_close(eventfds[0]);
        return -1;
}

int eventfd_send_state(int efd, eventfd_t s) {
        return eventfd_write(efd, s);
}

/*
 * Receive an eventfd state on the eventfd file descriptor.
 *
 * If the third argument is set to a value other than zero, then this
 * function will compare the received value with this argument and set
 * the return value.
 *
 * On success return 0. On error, -1 will be returned, and errno will
 * be set appropriately.
 */
int eventfd_recv_state(int efd, eventfd_t *e, eventfd_t s) {
        int ret;

        ret = eventfd_read(efd, e);
        if (ret < 0)
                return ret;
        else if (s != 0 && *e != s) {
                errno = EINVAL;
                return -1;
        }

        return 0;
}

/*
 * Receive the EVENTFD_START state on the eventfd file descriptor.
 *
 * On Success return 0. On error, -1 will be returned, and errno will
 * be set appropriately.
 */
int eventfd_recv_start(int efd) {
        eventfd_t e = EVENTFD_INIT;
        return eventfd_recv_state(efd, &e, EVENTFD_START);
}

/*
 * Receive the EVENTFD_PARENT_SUCCEEDED state on the eventfd file
 * descriptor.
 *
 * On Success return 0. On error, -1 will be returned, and errno will
 * be set appropriately.
 */
int eventfd_parent_succeeded(int efd) {
        eventfd_t e = EVENTFD_INIT;
        return eventfd_recv_state(efd, &e, EVENTFD_PARENT_SUCCEEDED);
}

/*
 * Receive the EVENTFD_CHILD_SUCCEEDED state on the eventfd file
 * descriptor.
 *
 * On Success return 0. On error, -1 will be returned, and errno will
 * be set appropriately.
 */
int eventfd_child_succeeded(int efd) {
        eventfd_t e = EVENTFD_INIT;
        return eventfd_recv_state(efd, &e, EVENTFD_CHILD_SUCCEEDED);
}
