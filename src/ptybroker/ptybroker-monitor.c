/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/epoll.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "iovec-util.h"
#include "log.h"
#include "ptybroker.h"
#include "ptybroker-monitor.h"
#include "ptybroker-pty.h"

PseudoTTYMonitor *pseudo_tty_monitor_free(PseudoTTYMonitor *monitor) {
        if (!monitor)
                return NULL;

        if (monitor->pty) {
                LIST_REMOVE(monitors, monitor->pty->monitors, monitor);
                monitor->pty->n_monitors--;
        }

        sd_event_source_disable_unref(monitor->io_event_source);

        if (monitor->link) {
                sd_varlink_set_userdata(monitor->link, NULL);
                sd_varlink_unref(monitor->link);
        }

        iovec_done(&monitor->buffer);

        return mfree(monitor);
}

static int pseudo_tty_monitor_write(PseudoTTYMonitor *monitor, int fd) {
        assert(monitor);
        assert(fd >= 0);

        if (monitor->buffer.iov_len <= 0)
                return 0;

        ssize_t n = write(fd, monitor->buffer.iov_base, monitor->buffer.iov_len);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                return log_error_errno(errno, "Failed to write to monitor socket: %m");
        }

        assert_se(iovec_reduce(&monitor->buffer, n));
        return 1;
}

static int pseudo_tty_monitor_read(PseudoTTYMonitor *monitor, int fd) {
        assert(monitor);
        assert(fd >= 0);

        if (monitor->pty->frontend_write_buffer.iov_len >= BUFFER_MAX)
                return 0;

        size_t left = LESS_BY(BUFFER_MAX, monitor->pty->frontend_write_buffer.iov_len);
        if (left <= 0)
                return 0;

        size_t add = MIN(left, LONG_LINE_MAX);

        if (!greedy_realloc(&monitor->pty->frontend_write_buffer.iov_base, monitor->pty->frontend_write_buffer.iov_len + add, 1))
                return log_oom();

        void *p = (uint8_t*) monitor->pty->frontend_write_buffer.iov_base + monitor->pty->frontend_write_buffer.iov_len;
        ssize_t n = read(fd, p, add);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                return log_error_errno(errno, "Failed to read from monitor socket: %m");
        }
        if (n == 0) /* Propagate EOF as proper error */
                return log_error_errno(SYNTHETIC_ERRNO(ECONNRESET), "Monitor EOF: %m");

        assert((size_t) n <= add);
        monitor->pty->frontend_write_buffer.iov_len += n;

        return 1;
}

int pseudo_tty_monitor_set_events(PseudoTTYMonitor *monitor) {
        int r;

        assert(monitor);

        uint32_t events = 0;
        if (monitor->buffer.iov_len > 0)
                events |= EPOLLOUT;
        if (monitor->pty->frontend_write_buffer.iov_len < BUFFER_MAX)
                events |= EPOLLIN;

        r = sd_event_source_set_io_events(monitor->io_event_source, events);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust I/O event mask for monitor socket: %m");

        return 0;
}

static int on_monitor_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        PseudoTTYMonitor *monitor = ASSERT_PTR(userdata);
        int r;

        assert(s);
        assert(fd >= 0);

        r = 0;
        RET_GATHER(r, pseudo_tty_monitor_write(monitor, fd));
        RET_GATHER(r, pseudo_tty_monitor_read(monitor, fd));
        if (r < 0)
                goto fail;

        /* NB: We don't call the monitor-specific pseudo_tty_monitor_set_events() call here, but the
         * pseudo_tty_set_events() call that applies to the whole pty. That's because having progressed here
         * might allow progress on the pty too. Note that pseudo_tty_set_events() will call back into
         * pseudo_tty_monitor_set_events() */
        r = pseudo_tty_set_events(monitor->pty);
        if (r < 0)
                goto fail;

        return 0;

fail:
        PseudoTTY *hang_up_pty = monitor->hang_up_on_disconnect ? monitor->pty : NULL;
        pseudo_tty_monitor_free(monitor);

        if (hang_up_pty)
                (void) pseudo_tty_vhangup(hang_up_pty);

        return r;
}

static int on_upgrade(sd_varlink *vl, int _input_fd, int _output_fd, void *userdata) {
        /* The fds are donated to us, no matter what, hence take possession of them right-away */
        _cleanup_close_ int input_fd = TAKE_FD(_input_fd), output_fd = TAKE_FD(_output_fd);
        PseudoTTYMonitor *monitor = ASSERT_PTR(userdata);
        int r;

        assert(vl);
        assert(input_fd >= 0);
        assert(output_fd >= 0);

        r = same_fd(input_fd, output_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to detect if input/output fds are the same: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADF), "Cannot operate with distinct input/output fds.");

        r = fd_nonblock(input_fd, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable non-blocking mode on upgraded socket: %m");

        assert(monitor->link == vl);
        monitor->link = sd_varlink_unref(monitor->link);

        assert(!monitor->io_event_source);
        r = sd_event_add_io(monitor->pty->manager->event, &monitor->io_event_source, input_fd, /* events= */ 0, on_monitor_io, monitor);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate monitor IO event: %m");
                goto fail;
        }

        r = sd_event_source_set_io_fd_own(monitor->io_event_source, true);
        if (r < 0) {
                log_error_errno(r, "Failed to pass ownership of monitor fd to IO event: %m");
                goto fail;
        }

        TAKE_FD(input_fd); /* ownership is now passed */

        r = pseudo_tty_monitor_set_events(monitor);
        if (r < 0)
                goto fail;

        return 0;

fail:
        pseudo_tty_monitor_free(monitor);
        return r;
}

int pseudo_tty_monitor_new(sd_varlink *link, PseudoTTYMonitor **ret) {
        int r;

        assert(link);
        assert(ret);

        _cleanup_(pseudo_tty_monitor_freep) PseudoTTYMonitor *monitor = new(PseudoTTYMonitor, 1);
        if (!monitor)
                return -ENOMEM;

        *monitor = (PseudoTTYMonitor) {
                .link = sd_varlink_ref(link),
        };

        r = sd_varlink_bind_upgrade(link, on_upgrade);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(monitor);
        return 0;
}

void pseudo_tty_monitor_link(PseudoTTYMonitor *monitor, PseudoTTY *pty) {
        assert(monitor);
        assert(pty);

        LIST_PREPEND(monitors, pty->monitors, monitor);
        pty->n_monitors++;
        monitor->pty = pty;

        sd_varlink_set_userdata(monitor->link, monitor);
        return;
}

size_t pseudo_tty_monitor_space(PseudoTTYMonitor *monitor) {
        assert(monitor);

        assert(monitor->buffer.iov_len <= BUFFER_MAX);
        return BUFFER_MAX - monitor->buffer.iov_len;
}
