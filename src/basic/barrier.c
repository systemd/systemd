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

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <unistd.h>

#include "barrier.h"
#include "fd-util.h"
#include "macro.h"
#include "util.h"

/**
 * Barriers
 * This barrier implementation provides a simple synchronization method based
 * on file-descriptors that can safely be used between threads and processes. A
 * barrier object contains 2 shared counters based on eventfd. Both processes
 * can now place barriers and wait for the other end to reach a random or
 * specific barrier.
 * Barriers are numbered, so you can either wait for the other end to reach any
 * barrier or the last barrier that you placed. This way, you can use barriers
 * for one-way *and* full synchronization. Note that even-though barriers are
 * numbered, these numbers are internal and recycled once both sides reached the
 * same barrier (implemented as a simple signed counter). It is thus not
 * possible to address barriers by their ID.
 *
 * Barrier-API: Both ends can place as many barriers via barrier_place() as
 * they want and each pair of barriers on both sides will be implicitly linked.
 * Each side can use the barrier_wait/sync_*() family of calls to wait for the
 * other side to place a specific barrier. barrier_wait_next() waits until the
 * other side calls barrier_place(). No links between the barriers are
 * considered and this simply serves as most basic asynchronous barrier.
 * barrier_sync_next() is like barrier_wait_next() and waits for the other side
 * to place their next barrier via barrier_place(). However, it only waits for
 * barriers that are linked to a barrier we already placed. If the other side
 * already placed more barriers than we did, barrier_sync_next() returns
 * immediately.
 * barrier_sync() extends barrier_sync_next() and waits until the other end
 * placed as many barriers via barrier_place() as we did. If they already placed
 * as many as we did (or more), it returns immediately.
 *
 * Additionally to basic barriers, an abortion event is available.
 * barrier_abort() places an abortion event that cannot be undone. An abortion
 * immediately cancels all placed barriers and replaces them. Any running and
 * following wait/sync call besides barrier_wait_abortion() will immediately
 * return false on both sides (otherwise, they always return true).
 * barrier_abort() can be called multiple times on both ends and will be a
 * no-op if already called on this side.
 * barrier_wait_abortion() can be used to wait for the other side to call
 * barrier_abort() and is the only wait/sync call that does not return
 * immediately if we aborted outself. It only returns once the other side
 * called barrier_abort().
 *
 * Barriers can be used for in-process and inter-process synchronization.
 * However, for in-process synchronization you could just use mutexes.
 * Therefore, main target is IPC and we require both sides to *not* share the FD
 * table. If that's given, barriers provide target tracking: If the remote side
 * exit()s, an abortion event is implicitly queued on the other side. This way,
 * a sync/wait call will be woken up if the remote side crashed or exited
 * unexpectedly. However, note that these abortion events are only queued if the
 * barrier-queue has been drained. Therefore, it is safe to place a barrier and
 * exit. The other side can safely wait on the barrier even though the exit
 * queued an abortion event. Usually, the abortion event would overwrite the
 * barrier, however, that's not true for exit-abortion events. Those are only
 * queued if the barrier-queue is drained (thus, the receiving side has placed
 * more barriers than the remote side).
 */

/**
 * barrier_create() - Initialize a barrier object
 * @obj: barrier to initialize
 *
 * This initializes a barrier object. The caller is responsible of allocating
 * the memory and keeping it valid. The memory does not have to be zeroed
 * beforehand.
 * Two eventfd objects are allocated for each barrier. If allocation fails, an
 * error is returned.
 *
 * If this function fails, the barrier is reset to an invalid state so it is
 * safe to call barrier_destroy() on the object regardless whether the
 * initialization succeeded or not.
 *
 * The caller is responsible to destroy the object via barrier_destroy() before
 * releasing the underlying memory.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int barrier_create(Barrier *b) {
        _cleanup_(barrier_destroyp) Barrier *staging = b;
        int r;

        assert(b);

        b->me = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (b->me < 0)
                return -errno;

        b->them = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (b->them < 0)
                return -errno;

        r = pipe2(b->pipe, O_CLOEXEC | O_NONBLOCK);
        if (r < 0)
                return -errno;

        staging = NULL;
        return 0;
}

/**
 * barrier_destroy() - Destroy a barrier object
 * @b: barrier to destroy or NULL
 *
 * This destroys a barrier object that has previously been passed to
 * barrier_create(). The object is released and reset to invalid
 * state. Therefore, it is safe to call barrier_destroy() multiple
 * times or even if barrier_create() failed. However, barrier must be
 * always initialized with BARRIER_NULL.
 *
 * If @b is NULL, this is a no-op.
 */
void barrier_destroy(Barrier *b) {
        if (!b)
                return;

        b->me = safe_close(b->me);
        b->them = safe_close(b->them);
        safe_close_pair(b->pipe);
        b->barriers = 0;
}

/**
 * barrier_set_role() - Set the local role of the barrier
 * @b: barrier to operate on
 * @role: role to set on the barrier
 *
 * This sets the roles on a barrier object. This is needed to know
 * which side of the barrier you're on. Usually, the parent creates
 * the barrier via barrier_create() and then calls fork() or clone().
 * Therefore, the FDs are duplicated and the child retains the same
 * barrier object.
 *
 * Both sides need to call barrier_set_role() after fork() or clone()
 * are done. If this is not done, barriers will not work correctly.
 *
 * Note that barriers could be supported without fork() or clone(). However,
 * this is currently not needed so it hasn't been implemented.
 */
void barrier_set_role(Barrier *b, unsigned int role) {
        int fd;

        assert(b);
        assert(role == BARRIER_PARENT || role == BARRIER_CHILD);
        /* make sure this is only called once */
        assert(b->pipe[0] >= 0 && b->pipe[1] >= 0);

        if (role == BARRIER_PARENT)
                b->pipe[1] = safe_close(b->pipe[1]);
        else {
                b->pipe[0] = safe_close(b->pipe[0]);

                /* swap me/them for children */
                fd = b->me;
                b->me = b->them;
                b->them = fd;
        }
}

/* places barrier; returns false if we aborted, otherwise true */
static bool barrier_write(Barrier *b, uint64_t buf) {
        ssize_t len;

        /* prevent new sync-points if we already aborted */
        if (barrier_i_aborted(b))
                return false;

        do {
                len = write(b->me, &buf, sizeof(buf));
        } while (len < 0 && IN_SET(errno, EAGAIN, EINTR));

        if (len != sizeof(buf))
                goto error;

        /* lock if we aborted */
        if (buf >= (uint64_t)BARRIER_ABORTION) {
                if (barrier_they_aborted(b))
                        b->barriers = BARRIER_WE_ABORTED;
                else
                        b->barriers = BARRIER_I_ABORTED;
        } else if (!barrier_is_aborted(b))
                b->barriers += buf;

        return !barrier_i_aborted(b);

error:
        /* If there is an unexpected error, we have to make this fatal. There
         * is no way we can recover from sync-errors. Therefore, we close the
         * pipe-ends and treat this as abortion. The other end will notice the
         * pipe-close and treat it as abortion, too. */

        safe_close_pair(b->pipe);
        b->barriers = BARRIER_WE_ABORTED;
        return false;
}

/* waits for barriers; returns false if they aborted, otherwise true */
static bool barrier_read(Barrier *b, int64_t comp) {
        if (barrier_they_aborted(b))
                return false;

        while (b->barriers > comp) {
                struct pollfd pfd[2] = {
                        { .fd = b->pipe[0] >= 0 ? b->pipe[0] : b->pipe[1],
                          .events = POLLHUP },
                        { .fd = b->them,
                          .events = POLLIN }};
                uint64_t buf;
                int r;

                r = poll(pfd, 2, -1);
                if (r < 0 && IN_SET(errno, EAGAIN, EINTR))
                        continue;
                else if (r < 0)
                        goto error;

                if (pfd[1].revents) {
                        ssize_t len;

                        /* events on @them signal new data for us */
                        len = read(b->them, &buf, sizeof(buf));
                        if (len < 0 && IN_SET(errno, EAGAIN, EINTR))
                                continue;

                        if (len != sizeof(buf))
                                goto error;
                } else if (pfd[0].revents & (POLLHUP | POLLERR | POLLNVAL))
                        /* POLLHUP on the pipe tells us the other side exited.
                         * We treat this as implicit abortion. But we only
                         * handle it if there's no event on the eventfd. This
                         * guarantees that exit-abortions do not overwrite real
                         * barriers. */
                        buf = BARRIER_ABORTION;
                else
                        continue;

                /* lock if they aborted */
                if (buf >= (uint64_t)BARRIER_ABORTION) {
                        if (barrier_i_aborted(b))
                                b->barriers = BARRIER_WE_ABORTED;
                        else
                                b->barriers = BARRIER_THEY_ABORTED;
                } else if (!barrier_is_aborted(b))
                        b->barriers -= buf;
        }

        return !barrier_they_aborted(b);

error:
        /* If there is an unexpected error, we have to make this fatal. There
         * is no way we can recover from sync-errors. Therefore, we close the
         * pipe-ends and treat this as abortion. The other end will notice the
         * pipe-close and treat it as abortion, too. */

        safe_close_pair(b->pipe);
        b->barriers = BARRIER_WE_ABORTED;
        return false;
}

/**
 * barrier_place() - Place a new barrier
 * @b: barrier object
 *
 * This places a new barrier on the barrier object. If either side already
 * aborted, this is a no-op and returns "false". Otherwise, the barrier is
 * placed and this returns "true".
 *
 * Returns: true if barrier was placed, false if either side aborted.
 */
bool barrier_place(Barrier *b) {
        assert(b);

        if (barrier_is_aborted(b))
                return false;

        barrier_write(b, BARRIER_SINGLE);
        return true;
}

/**
 * barrier_abort() - Abort the synchronization
 * @b: barrier object to abort
 *
 * This aborts the barrier-synchronization. If barrier_abort() was already
 * called on this side, this is a no-op. Otherwise, the barrier is put into the
 * ABORT-state and will stay there. The other side is notified about the
 * abortion. Any following attempt to place normal barriers or to wait on normal
 * barriers will return immediately as "false".
 *
 * You can wait for the other side to call barrier_abort(), too. Use
 * barrier_wait_abortion() for that.
 *
 * Returns: false if the other side already aborted, true otherwise.
 */
bool barrier_abort(Barrier *b) {
        assert(b);

        barrier_write(b, BARRIER_ABORTION);
        return !barrier_they_aborted(b);
}

/**
 * barrier_wait_next() - Wait for the next barrier of the other side
 * @b: barrier to operate on
 *
 * This waits until the other side places its next barrier. This is independent
 * of any barrier-links and just waits for any next barrier of the other side.
 *
 * If either side aborted, this returns false.
 *
 * Returns: false if either side aborted, true otherwise.
 */
bool barrier_wait_next(Barrier *b) {
        assert(b);

        if (barrier_is_aborted(b))
                return false;

        barrier_read(b, b->barriers - 1);
        return !barrier_is_aborted(b);
}

/**
 * barrier_wait_abortion() - Wait for the other side to abort
 * @b: barrier to operate on
 *
 * This waits until the other side called barrier_abort(). This can be called
 * regardless whether the local side already called barrier_abort() or not.
 *
 * If the other side has already aborted, this returns immediately.
 *
 * Returns: false if the local side aborted, true otherwise.
 */
bool barrier_wait_abortion(Barrier *b) {
        assert(b);

        barrier_read(b, BARRIER_THEY_ABORTED);
        return !barrier_i_aborted(b);
}

/**
 * barrier_sync_next() - Wait for the other side to place a next linked barrier
 * @b: barrier to operate on
 *
 * This is like barrier_wait_next() and waits for the other side to call
 * barrier_place(). However, this only waits for linked barriers. That means, if
 * the other side already placed more barriers than (or as much as) we did, this
 * returns immediately instead of waiting.
 *
 * If either side aborted, this returns false.
 *
 * Returns: false if either side aborted, true otherwise.
 */
bool barrier_sync_next(Barrier *b) {
        assert(b);

        if (barrier_is_aborted(b))
                return false;

        barrier_read(b, MAX((int64_t)0, b->barriers - 1));
        return !barrier_is_aborted(b);
}

/**
 * barrier_sync() - Wait for the other side to place as many barriers as we did
 * @b: barrier to operate on
 *
 * This is like barrier_sync_next() but waits for the other side to call
 * barrier_place() as often as we did (in total). If they already placed as much
 * as we did (or more), this returns immediately instead of waiting.
 *
 * If either side aborted, this returns false.
 *
 * Returns: false if either side aborted, true otherwise.
 */
bool barrier_sync(Barrier *b) {
        assert(b);

        if (barrier_is_aborted(b))
                return false;

        barrier_read(b, 0);
        return !barrier_is_aborted(b);
}
