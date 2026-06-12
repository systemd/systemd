/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "iovec-util.h"
#include "log.h"
#include "ptybroker.h"
#include "ptybroker-monitor.h"
#include "ptybroker-pty.h"

PseudoTTYMonitor* pseudo_tty_monitor_free(PseudoTTYMonitor *monitor) {
        if (!monitor)
                return NULL;

        if (monitor->pty) {
                LIST_REMOVE(monitors, monitor->pty->monitors, monitor);
                monitor->pty->n_monitors--;
        }

        sd_event_source_disable_unref(monitor->io_event_source);
        sd_event_source_disable_unref(monitor->disconnect_event_source);

        if (monitor->link) {
                /* If the link is still around here the connection never completed its upgrade: close it, so
                 * that the client doesn't hang on to a connection nobody will ever service. */
                sd_varlink_set_userdata(monitor->link, NULL);
                sd_varlink_close_unref(monitor->link);
        }

        iovec_done(&monitor->buffer);

        return mfree(monitor);
}

void pseudo_tty_monitor_disconnect(PseudoTTYMonitor *monitor) {
        assert(monitor);

        /* Frees the monitor because its connection went away, and then either hangs up the pty (if requested)
         * or re-evaluates the pty's event mask: this monitor's buffer might have been what throttled reading
         * from the pty. */

        PseudoTTY *pty = monitor->pty;
        bool hang_up = monitor->hang_up_on_disconnect;

        pseudo_tty_monitor_free(monitor);

        if (!pty)
                return;

        if (hang_up)
                (void) pseudo_tty_vhangup(pty);

        (void) pseudo_tty_set_events(pty);
}

static int on_disconnect_defer(sd_event_source *s, void *userdata) {
        PseudoTTYMonitor *monitor = ASSERT_PTR(userdata);

        assert(s);

        /* If the link is still set the connection upgrade never completed, but the connection is gone
         * nonetheless. Nobody will ever service the monitor hence, drop it. */
        if (!monitor->link)
                return 0;

        log_debug("Monitor connection went away before its upgrade completed, dropping monitor.");
        pseudo_tty_monitor_disconnect(monitor);
        return 0;
}

void pseudo_tty_monitor_on_link_disconnect(PseudoTTYMonitor *monitor) {
        int r;

        assert(monitor);

        /* Called whenever the Varlink connection of the monitor is disconnected. Note that this also happens
         * right before the upgrade callback is invoked, hence we can't free the monitor right-away. Instead,
         * check from a deferred event source whether the upgrade happened in the meantime. */

        if (!monitor->link || !monitor->pty || monitor->disconnect_event_source)
                return;

        r = sd_event_add_defer(monitor->pty->manager->event, &monitor->disconnect_event_source, on_disconnect_defer, monitor);
        if (r < 0) {
                log_warning_errno(r, "Failed to allocate deferred event source for monitor disconnect, dropping monitor right-away: %m");
                /* Make sure the upgrade callback doesn't reference the monitor anymore, then drop it */
                pseudo_tty_monitor_disconnect(monitor);
                return;
        }

        (void) sd_event_source_set_description(monitor->disconnect_event_source, "monitor-disconnect");
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

        assert_se(iovec_consume(&monitor->buffer, n));
        return n > 0;
}

int pseudo_tty_monitor_flush(PseudoTTYMonitor *monitor) {
        assert(monitor);

        /* Writes out as much of the buffered output as the connection takes right now, without blocking */

        if (!monitor->io_event_source) /* The connection upgrade hasn't completed yet */
                return 0;

        int fd = sd_event_source_get_io_fd(monitor->io_event_source);
        if (fd < 0)
                return fd;

        return pseudo_tty_monitor_write(monitor, fd);
}

static int pseudo_tty_monitor_push_output(PseudoTTYMonitor *monitor, const void *data, size_t n) {
        assert(monitor);
        assert(data || n == 0);

        if (n == SIZE_MAX)
                n = strlen(data);
        if (n == 0)
                return 0;

        size_t m;
        if (!ADD_SAFE(&m, monitor->buffer.iov_len, n))
                return -ENOMEM;

        if (!greedy_realloc(&monitor->buffer.iov_base, m, 1))
                return -ENOMEM;

        memcpy((uint8_t*) monitor->buffer.iov_base + monitor->buffer.iov_len, data, n);
        monitor->buffer.iov_len = m;

        return 0;
}

int pseudo_tty_monitor_push_pending(PseudoTTYMonitor *monitor) {
        assert(monitor);
        assert(monitor->pty);

        /* If we are setting up a new monitor, let's immediately enqueue any incomplete lines still queued in the pty */

        struct iovec v = monitor->pty->frontend_read_buffer;

        /* Skip over initial newlines */
        for (;;) {
                if (!iovec_is_set(&v))
                        return 0;

                if (end_of_line_from_char(*(char*) v.iov_base) == EOL_NONE)
                        break;

                iovec_inc(&v, 1);
        }

        return pseudo_tty_monitor_push_output(monitor, v.iov_base, v.iov_len);
}

static int pseudo_tty_monitor_read(PseudoTTYMonitor *monitor, int fd) {
        assert(monitor);
        assert(fd >= 0);

        if (monitor->pty->frontend_write_buffer.iov_len >= BUFFER_MAX)
                return 0;

        size_t left = BUFFER_MAX - monitor->pty->frontend_write_buffer.iov_len;
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
        if (n == 0) /* Propagate EOF as proper error. This is a normal lifecycle event, hence log about it
                     * only at debug level. */
                return log_debug_errno(SYNTHETIC_ERRNO(ECONNRESET), "Monitor disconnected.");

        assert((size_t) n <= add);
        monitor->pty->frontend_write_buffer.iov_len += n;

        return 1;
}

int pseudo_tty_monitor_set_events(PseudoTTYMonitor *monitor) {
        int r;

        assert(monitor);

        if (!monitor->io_event_source) /* The connection upgrade hasn't completed yet, nothing to watch so far */
                return 0;

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

        /* Handle hangups only after processing any data still queued. Note that we might not see EOF on
         * read() if we didn't read due to a full buffer, and epoll will keep reporting EPOLLHUP/EPOLLERR
         * even with an empty event mask, hence handle them explicitly. */
        if (revents & (EPOLLHUP|EPOLLERR)) {
                r = log_debug_errno(SYNTHETIC_ERRNO(ECONNRESET), "Monitor disconnected.");
                goto fail;
        }

        /* NB: We don't call the monitor-specific pseudo_tty_monitor_set_events() call here, but the
         * pseudo_tty_set_events() call that applies to the whole pty. That's because having progressed here
         * might allow progress on the pty too. Note that pseudo_tty_set_events() will call back into
         * pseudo_tty_monitor_set_events() */
        r = pseudo_tty_set_events(monitor->pty);
        if (r < 0)
                goto fail;

        return 0;

fail:
        pseudo_tty_monitor_disconnect(monitor);
        return r;
}

static int on_upgrade(sd_varlink *vl, int _input_fd, int _output_fd, void *userdata) {
        /* The fds are donated to us, no matter what, hence take possession of them right-away */
        _cleanup_close_ int input_fd = TAKE_FD(_input_fd), output_fd = TAKE_FD(_output_fd);
        PseudoTTYMonitor *monitor = userdata;
        int r;

        assert(vl);
        assert(input_fd >= 0);
        assert(output_fd >= 0);

        /* The upgrade only completes once the client consumed the upgrade reply, which might take a while
         * (in particular if the client is slow to read a large track buffer). If the monitor went away in
         * the meantime (because its pty was hung up), nobody is left to take the connection: drop it. */
        if (!monitor)
                return log_debug_errno(SYNTHETIC_ERRNO(ESTALE), "Monitor went away before its connection upgrade completed, closing connection.");

        r = same_fd(input_fd, output_fd);
        if (r < 0) {
                log_error_errno(r, "Failed to detect if input/output fds are the same: %m");
                goto fail;
        }
        if (r == 0) {
                r = log_error_errno(SYNTHETIC_ERRNO(EBADF), "Cannot operate with distinct input/output fds.");
                goto fail;
        }

        r = fd_nonblock(input_fd, true);
        if (r < 0) {
                log_error_errno(r, "Failed to enable non-blocking mode on upgraded socket: %m");
                goto fail;
        }

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
        pseudo_tty_monitor_disconnect(monitor);
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
}

size_t pseudo_tty_monitor_space(PseudoTTYMonitor *monitor) {
        assert(monitor);

        assert(monitor->buffer.iov_len <= BUFFER_MAX);
        return BUFFER_MAX - monitor->buffer.iov_len;
}
