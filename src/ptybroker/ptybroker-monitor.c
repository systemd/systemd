/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "ansi-seq.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "iovec-util.h"
#include "log.h"
#include "osc-winsize.h"
#include "ptybroker.h"
#include "ptybroker-monitor.h"
#include "ptybroker-pty.h"

/* Upper bound on how much of an incomplete ANSI sequence we may hold back on the input stream, in order to
 * filter out OSC 2811 replies. The parser aborts sequences that grow beyond ANSI_SEQ_STRING_MAX (which are
 * then passed through unscathed), hence held back data never exceeds that plus a few bytes of framing. */
#define INPUT_HOLD_MAX (ANSI_SEQ_STRING_MAX + 8U)

PseudoTTYMonitor* pseudo_tty_monitor_free(PseudoTTYMonitor *monitor) {
        if (!monitor)
                return NULL;

        if (monitor->pty) {
                LIST_REMOVE(monitors, monitor->pty->monitors, monitor);
                monitor->pty->n_monitors--;

                /* This monitor's dimensions no longer constrain the pty, re-determine the minimum */
                if (monitor->osc_winsize)
                        (void) pseudo_tty_sync_winsize(monitor->pty);

                /* Nor does its buffer space constrain the pty's readability anymore: refresh the pty's I/O
                 * event mask, so that a pty stalled by this monitor gets going again (unless the pty is on
                 * its way out anyway, in which case there's no point). */
                if (!monitor->pty->in_free_queue)
                        (void) pseudo_tty_set_events(monitor->pty);
        }

        sd_event_source_disable_unref(monitor->io_event_source);

        if (monitor->link) {
                /* If the link is still around here the connection never completed its upgrade: close it, so
                 * that the client doesn't hang on to a connection nobody will ever service. */
                sd_varlink_set_userdata(monitor->link, NULL);
                sd_varlink_close_unref(monitor->link);
        }

        iovec_done(&monitor->buffer);
        iovec_done(&monitor->input_hold);

        ansi_seq_parser_done(&monitor->output_parser);
        ansi_seq_parser_done(&monitor->input_parser);

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
        return n > 0;
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

        /* NB: this goes through the same path as regular pty output, so that the sequence boundary tracking
         * sees every byte that is sent to the monitor, in particular if the pending line ends in the middle
         * of a sequence. */
        return pseudo_tty_monitor_enqueue_output(monitor, v.iov_base, v.iov_len);
}

static int pseudo_tty_monitor_flush_subscribe(PseudoTTYMonitor *monitor) {
        int r;

        assert(monitor);

        /* Appends a pending OSC 2811 subscribe sequence to the monitor's output buffer, but only at a safe
         * position, i.e. never in the middle of an ANSI sequence that is part of the regular stream. */

        if (!monitor->subscribe_pending)
                return 0;

        if (monitor->output_parser.state != ANSI_SEQ_STATE_GROUND)
                return 0;

        _cleanup_free_ char *seq = NULL;
        r = osc_winsize_format(OSC_WINSIZE_SUBSCRIBE, monitor->columns, monitor->lines, &seq);
        if (r < 0)
                return r;

        r = pseudo_tty_monitor_push_output(monitor, seq, SIZE_MAX);
        if (r < 0)
                return r;

        monitor->subscribe_pending = false;
        return 1;
}

static int pseudo_tty_monitor_request_winsize(PseudoTTYMonitor *monitor) {
        assert(monitor);

        /* (Re-)subscribes to dimension changes of the monitor's terminal, declaring the dimensions we
         * currently believe are in effect (or 0×0 if we don't know yet, forcing an immediate reply). */

        if (!monitor->osc_winsize)
                return 0;

        monitor->subscribe_pending = true;
        return pseudo_tty_monitor_flush_subscribe(monitor);
}

int pseudo_tty_monitor_enqueue_output(PseudoTTYMonitor *monitor, const void *data, size_t n) {
        int r;

        assert(monitor);
        assert(data || n == 0);

        /* Appends pty output data to the monitor's output buffer. If OSC 2811 handling is enabled, also
         * tracks ANSI sequence boundaries, so that we can insert our own sequences at safe positions. */

        if (!monitor->osc_winsize)
                return pseudo_tty_monitor_push_output(monitor, data, n);

        const char *q = data;
        FOREACH_ARRAY(c, q, n) {
                r = pseudo_tty_monitor_push_output(monitor, c, 1);
                if (r < 0)
                        return r;

                (void) ansi_seq_parser_feed_harder(&monitor->output_parser, *c);

                r = pseudo_tty_monitor_flush_subscribe(monitor);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int pseudo_tty_monitor_read(PseudoTTYMonitor *monitor, int fd) {
        int r;

        assert(monitor);
        assert(fd >= 0);

        struct iovec *fwb = &monitor->pty->frontend_write_buffer;

        if (fwb->iov_len >= BUFFER_MAX)
                return 0;

        size_t left = BUFFER_MAX - fwb->iov_len,
               add = MIN(left, LONG_LINE_MAX),
               offset = fwb->iov_len,
               hold = monitor->input_hold.iov_len; /* Non-zero only if OSC 2811 handling is on */

        if (!greedy_realloc(&fwb->iov_base, offset + hold + add, 1))
                return log_oom();

        /* Read directly into the pty's frontend write buffer, leaving room for any incomplete sequence
         * bytes we held back last time */
        ssize_t n = read(fd, (uint8_t*) fwb->iov_base + offset + hold, add);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                return log_error_errno(errno, "Failed to read from monitor socket: %m");
        }
        if (n == 0) /* Propagate EOF as proper error. This is a normal lifecycle event, hence log about it
                     * only at debug level. */
                return log_debug_errno(SYNTHETIC_ERRNO(ECONNRESET), "Monitor disconnected.");

        assert((size_t) n <= add);

        /* Reinsert the held back bytes right before the data we just read */
        if (hold > 0) {
                memcpy((uint8_t*) fwb->iov_base + offset, monitor->input_hold.iov_base, hold);
                monitor->input_hold.iov_len = 0;
        }

        fwb->iov_len = offset + hold + n;

        if (!monitor->osc_winsize)
                return 1;

        /* Now scan the data we just read for ANSI sequences, so that OSC 2811 reply sequences can be picked
         * out of the stream and consumed. The held back bytes have been fed to the parser last time already,
         * hence start with the new data; if we are in the middle of a sequence it begins where the held back
         * bytes were reinserted. */
        size_t begin = hold > 0 ? offset : SIZE_MAX;

        for (size_t i = offset + hold, inc = 1; i < fwb->iov_len; i += inc, inc = 1) {
                char c = ((const char*) fwb->iov_base)[i];

                r = ansi_seq_parser_feed(&monitor->input_parser, c);
                if (r < 0)
                        return log_error_errno(r, "Failed to process data from monitor socket: %m");

                switch (r) {

                case ANSI_SEQ_EVENT_TEXT:
                        break;

                case ANSI_SEQ_EVENT_SEQUENCE:
                        if (begin == SIZE_MAX)
                                begin = i;
                        break;

                case ANSI_SEQ_EVENT_END: {
                        assert(begin != SIZE_MAX);

                        const char *seq = ansi_seq_parser_string(&monitor->input_parser);
                        OscWinsize ws;

                        if (seq && monitor->input_parser.introducer == ']' &&
                            osc_winsize_parse(seq, &ws) > 0 &&
                            ws.type == OSC_WINSIZE_REPORT) { /* Ignore (i.e. pass through) reflected requests, as per spec */

                                /* An OSC 2811 reply: excise it from the buffer, and update our dimension data */
                                memmove((uint8_t*) fwb->iov_base + begin,
                                        (uint8_t*) fwb->iov_base + i + 1,
                                        fwb->iov_len - i - 1);
                                fwb->iov_len -= i + 1 - begin;
                                i = begin - 1; /* Continue right after the excised sequence (NB: the loop increments i again) */

                                monitor->columns = ws.columns;
                                monitor->lines = ws.lines;

                                r = pseudo_tty_sync_winsize(monitor->pty);
                                if (r < 0)
                                        return r;

                                /* Immediately resubscribe, declaring what we just learnt */
                                r = pseudo_tty_monitor_request_winsize(monitor);
                                if (r < 0)
                                        return r;
                        }

                        begin = SIZE_MAX;
                        break;
                }

                case ANSI_SEQ_EVENT_ABORT:
                        /* Not a valid sequence after all: leave it in the stream as it is, and process the
                         * current character again */
                        begin = SIZE_MAX;
                        inc = 0;
                        break;

                default:
                        assert_not_reached();
                }
        }

        /* If the buffer ends in the middle of a sequence, hold the incomplete sequence back, so that it
         * does not hit the pty before we know whether to excise it. Note that the parser gives up on
         * sequences that grow beyond ANSI_SEQ_STRING_MAX, hence the held back data is bounded. */
        if (begin != SIZE_MAX) {
                size_t tail = fwb->iov_len - begin;

                assert(tail <= INPUT_HOLD_MAX);

                if (!greedy_realloc(&monitor->input_hold.iov_base, tail, 1))
                        return log_oom();

                memcpy(monitor->input_hold.iov_base, (uint8_t*) fwb->iov_base + begin, tail);
                monitor->input_hold.iov_len = tail;

                fwb->iov_len = begin;
        }

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
        PseudoTTY *hang_up_pty;
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
        hang_up_pty = monitor->hang_up_on_disconnect ? monitor->pty : NULL;
        pseudo_tty_monitor_free(monitor);

        if (hang_up_pty)
                (void) pseudo_tty_vhangup(hang_up_pty);

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

        /* Query the monitor for its terminal dimensions, and subscribe to changes */
        r = pseudo_tty_monitor_request_winsize(monitor);
        if (r < 0) {
                log_error_errno(r, "Failed to enqueue terminal dimension subscription: %m");
                goto fail;
        }

        r = pseudo_tty_monitor_set_events(monitor);
        if (r < 0)
                goto fail;

        return 0;

fail:
        pseudo_tty_monitor_free(monitor);
        return r;
}

int pseudo_tty_monitor_new(sd_varlink *link, bool osc_winsize, PseudoTTYMonitor **ret) {
        int r;

        assert(link);
        assert(ret);

        _cleanup_(pseudo_tty_monitor_freep) PseudoTTYMonitor *monitor = new(PseudoTTYMonitor, 1);
        if (!monitor)
                return -ENOMEM;

        *monitor = (PseudoTTYMonitor) {
                .link = sd_varlink_ref(link),
                .osc_winsize = osc_winsize,
                .input_parser.capture = osc_winsize,
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

        /* NB: insertion of OSC 2811 sequences may push the buffer slightly beyond BUFFER_MAX, hence be
         * lenient here and saturate. */
        return LESS_BY((size_t) BUFFER_MAX, monitor->buffer.iov_len);
}
