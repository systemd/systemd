/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "hashmap.h"
#include "inotify-util.h"
#include "iovec-util.h"
#include "list.h"
#include "log.h"
#include "pidref.h"
#include "process-util.h"
#include "ptybroker-monitor.h"
#include "ptybroker-pty.h"
#include "ptybroker.h"
#include "set.h"
#include "string-table.h"
#include "string-util.h"
#include "terminal-util.h"
#include "varlink-util.h"

#define TRACK_BUFFER_LINES_MAX (4U * 1024U)
#define TRACK_BUFFER_BYTES_MAX (4U * U64_MB)

/* We force a line out after LONG_LINE_MAX, hence make sure we can read as much into our buffers */
assert_cc(LONG_LINE_MAX < BUFFER_MAX);

/* Enforce that the track buffer definitely fits at least one line (as read from the pty, i.e. before TAB
 * expansion, which might make it larger, see below) */
assert_cc(LONG_LINE_MAX < TRACK_BUFFER_BYTES_MAX);

static int pseudo_tty_track_buffer_add_line(PseudoTTY *pty, char *line) {
        assert(pty);
        assert(line);

        /* Appends the specified line to the track buffer ring, dropping the oldest line once the ring is at
         * capacity, and as many further old lines as necessary to stay below the byte budget. Consumes the
         * line on success. Returns -E2BIG (without consuming the line) if the line is too large to ever fit
         * into the track buffer. */

        /* Lines are cut at LONG_LINE_MAX when read from the pty, but strip_tab_ansi() expands each TAB to
         * eight spaces, hence a line might have grown considerably since. Don't even try to store it if it
         * cannot fit. */
        size_t l = strlen(line);
        if (l >= TRACK_BUFFER_BYTES_MAX)
                return -E2BIG;

        size_t allocate = MIN(pty->track_buffer_allocated_lines + 1, TRACK_BUFFER_LINES_MAX);
        if (allocate > pty->track_buffer_allocated_lines) {
                if (!GREEDY_REALLOC0(pty->track_buffer, allocate))
                        return -ENOMEM;

                pty->track_buffer_allocated_lines = allocate;
        }

        pty->track_buffer_next_line %= pty->track_buffer_allocated_lines;

        /* Delete old lines, starting with the oldest one (which is the slot we are about to overwrite,
         * hence always drop it), continuing with the next oldest ones for as long as the buffer would
         * otherwise exceed the byte limit. */
        for (size_t i = 0; i < pty->track_buffer_allocated_lines; i++) {
                if (i > 0 && pty->track_buffer_n_bytes + l < TRACK_BUFFER_BYTES_MAX)
                        break;

                char **slot = pty->track_buffer + (pty->track_buffer_next_line + i) % pty->track_buffer_allocated_lines;

                /* Free unless already NULLed out on an earlier iteration */
                if (*slot) {
                        size_t k = strlen(*slot);
                        assert(pty->track_buffer_n_bytes >= k);
                        pty->track_buffer_n_bytes -= k;
                        *slot = mfree(*slot);
                }
        }

        /* insert new line */
        assert(pty->track_buffer_n_bytes + l < TRACK_BUFFER_BYTES_MAX);
        pty->track_buffer_n_bytes += l;
        pty->track_buffer[pty->track_buffer_next_line] = line;
        pty->track_buffer_next_line++;

        return 0;
}

PseudoTTY* pseudo_tty_free(PseudoTTY *pty) {
        if (!pty)
                return NULL;

        while (pty->monitors)
                pseudo_tty_monitor_free(pty->monitors);

        if (pty->in_free_queue) {
                assert(pty->manager);
                LIST_REMOVE(free_queue, pty->manager->ptys_free_queue, pty);
        }

        if (pty->manager) {
                assert(pty->name);
                hashmap_remove(pty->manager->ptys, pty->name);
        }

        pty->name = mfree(pty->name);
        pty->description = mfree(pty->description);
        pty->tag = mfree(pty->tag);

        terminal_settings_done(&pty->terminal_settings);

        sd_event_source_disable_unref(pty->io_event_source);

        pty->frontend_fd = safe_close(pty->frontend_fd);
        pty->backend_fd = safe_close(pty->backend_fd);
        pty->pin_fd = safe_close(pty->pin_fd);

        free(pty->backend_path);
        free(pty->unit);

        sd_varlink_close_unref(pty->start_shell_link);

        sd_varlink_unref(pty->acquire_link);
        sd_json_variant_unref(pty->acquire_reply);

        free_many_charp(pty->track_buffer, pty->track_buffer_allocated_lines);
        free(pty->track_buffer);

        iovec_done(&pty->frontend_write_buffer);
        iovec_done(&pty->frontend_read_buffer);

        sd_event_source_disable_unref(pty->backend_inotify_event_source);

        set_free(pty->vhangup_links);
        sd_event_source_disable_unref(pty->vhangup_event_source);

        pidref_done(&pty->owner_pidref);

        return mfree(pty);
}

static int pseudo_tty_write(PseudoTTY *pty) {
        assert(pty);
        assert(pty->frontend_fd >= 0);

        if (pty->frontend_write_buffer.iov_len <= 0)
                return 0;

        ssize_t n = write(pty->frontend_fd, pty->frontend_write_buffer.iov_base, pty->frontend_write_buffer.iov_len);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                return log_error_errno(errno, "Failed to write to pseudo TTY: %m");
        }

        assert_se(iovec_reduce(&pty->frontend_write_buffer, n));
        return 1;
}

static int pseudo_tty_read(PseudoTTY *pty) {
        assert(pty);
        assert(pty->frontend_fd >= 0);

        /* First let's determine how much we can read. That's the minimum of our own scan buffer, and each
         * monitor's buffer */
        assert(pty->frontend_read_buffer.iov_len <= BUFFER_MAX);
        size_t left = BUFFER_MAX - pty->frontend_read_buffer.iov_len;
        LIST_FOREACH(monitors, monitor, pty->monitors) {
                if (left <= 0)
                        break;

                left = MIN(left, pseudo_tty_monitor_space(monitor));
        }
        if (left <= 0)
                return 0;
        /* Cap a single read at LONG_LINE_MAX so we don't allocate/read huge chunks at once, but never read
         * more than the smallest consumer's headroom, so that BUFFER_MAX stays a hard cap for every buffer. */
        size_t add = MIN(left, (size_t) LONG_LINE_MAX);

        /* Now extend the buffers according to our determination */
        if (!greedy_realloc(&pty->frontend_read_buffer.iov_base, pty->frontend_read_buffer.iov_len + add, 1))
                return log_oom();
        LIST_FOREACH(monitors, monitor, pty->monitors)
                if (!greedy_realloc(&monitor->buffer.iov_base, monitor->buffer.iov_len + add, 1))
                        return log_oom();

        /* And then read into our scan buffer first */
        void *p = (uint8_t*) pty->frontend_read_buffer.iov_base + pty->frontend_read_buffer.iov_len;
        ssize_t n = read(pty->frontend_fd, p, add);
        if (n < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;
                if (errno == EIO) /* The kernel reports EIO on the frontend once the backend has been hung up
                                   * or closed. This is a normal lifecycle event, hence log about it only at
                                   * debug level. */
                        return log_debug_errno(SYNTHETIC_ERRNO(ECONNRESET), "Hangup on pseudo TTY.");

                return log_error_errno(errno, "Failed to read from pseudo TTY: %m");
        }
        if (n == 0) /* Propagate EOF as proper error. This is a normal lifecycle event, hence log about it
                     * only at debug level. */
                return log_debug_errno(SYNTHETIC_ERRNO(ECONNRESET), "Hangup on pseudo TTY.");

        assert((size_t) n <= add);
        pty->frontend_read_buffer.iov_len += n;

        /* Copy the data we received to all monitors */
        LIST_FOREACH(monitors, m, pty->monitors) {
                memcpy((uint8_t*) m->buffer.iov_base + m->buffer.iov_len, p, n);
                m->buffer.iov_len += n;
        }

        return 1;
}

int pseudo_tty_set_events(PseudoTTY *pty) {
        int r;

        assert(pty);

        uint32_t events = 0;
        if (pty->frontend_write_buffer.iov_len > 0)
                events |= EPOLLOUT;

        bool readable = pty->frontend_read_buffer.iov_len < BUFFER_MAX;
        LIST_FOREACH(monitors, monitor, pty->monitors)  {
                readable = readable && pseudo_tty_monitor_space(monitor) > 0;

                /* Also refresh the monitors, since they read directly into our write buffer */
                r = pseudo_tty_monitor_set_events(monitor);
                if (r < 0)
                        return r;
        }

        if (readable)
                events |= EPOLLIN;

        if (!pty->io_event_source) /* Might already be gone, e.g. while a vhangup() is in progress */
                return 0;

        r = sd_event_source_set_io_events(pty->io_event_source, events);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust I/O event mask for pseudo TTY: %m");

        return 0;
}

static int pseudo_tty_log_line(PseudoTTY *pty, const char *line) {
        assert(pty);
        assert(line);

        if (pty->frontend_type != FRONTEND_LOG)
                return 0;

        _cleanup_free_ char *j = NULL;
        if (pty->tag) {
                j = strjoin(pty->tag, ": ", line);
                if (!j)
                        return log_oom();

                line = j;
        }

        /* The pidfd inode number is only available on kernel 6.9+, hence drop the field if we couldn't
         * acquire it. */
        if (pty->owner_pidref.fd_id > 0)
                log_struct(LOG_INFO,
                           LOG_ITEM("MESSAGE=%s", line),
                           LOG_ITEM("SYSLOG_IDENTIFIER=%s", pty->tag ?: pty->name),
                           LOG_ITEM("PTY=%s", pty->name),
                           LOG_ITEM("PTY_OWNER_PID=" PID_FMT, pty->owner_pidref.pid),
                           LOG_ITEM("PTY_OWNER_PIDFDID=%" PRIu64, pty->owner_pidref.fd_id),
                           LOG_ITEM("PTY_OWNER_UID=" UID_FMT, pty->owner_uid),
                           LOG_ITEM("PTY_OWNER_GID=" GID_FMT, pty->owner_gid));
        else
                log_struct(LOG_INFO,
                           LOG_ITEM("MESSAGE=%s", line),
                           LOG_ITEM("SYSLOG_IDENTIFIER=%s", pty->tag ?: pty->name),
                           LOG_ITEM("PTY=%s", pty->name),
                           LOG_ITEM("PTY_OWNER_PID=" PID_FMT, pty->owner_pidref.pid),
                           LOG_ITEM("PTY_OWNER_UID=" UID_FMT, pty->owner_uid),
                           LOG_ITEM("PTY_OWNER_GID=" GID_FMT, pty->owner_gid));

        return 0;
}

static int pseudo_tty_dispatch_line(PseudoTTY *pty, const char *p, size_t n) {
        int r;

        assert(pty);

        _cleanup_free_ char *line = memdup_suffix0(p, n);
        if (!line)
                return log_oom();

        if (!strip_tab_ansi(&line, /* _isz= */ NULL, /* highlight= */ NULL))
                return log_oom();

        /* Suppress empty lines */
        if (isempty(line))
                return 0;

        /* If logging is enabled, log to the journal */
        r = pseudo_tty_log_line(pty, line);
        if (r < 0)
                return r;

        /* Append it to the track buffer */
        r = pseudo_tty_track_buffer_add_line(pty, line);
        if (r == -E2BIG) {
                log_debug("Line of pseudo TTY '%s' too long for the track buffer, not tracking it.", strna(pty->name));
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to add line to track buffer: %m");

        TAKE_PTR(line);

        return 0;
}

static int pseudo_tty_process_line(PseudoTTY *pty, bool force_flush) {
        int r;

        assert(pty);

        char *begin = NULL, *e = pty->frontend_read_buffer.iov_base;
        size_t l = pty->frontend_read_buffer.iov_len;
        EndOfLine eol_mask = pty->eol_mask;

        while (l > 0) {
                size_t n_drop_extra;
                EndOfLine eol_found = end_of_line_from_char(*e);
                if (eol_found == EOL_NONE) {
                        /* A regular character */
                        if (!begin)
                                begin = e;

                        /* Check if this is maybe the last character in the buffer, and a flush is forced. If
                         * so, this is also an EOL marker. Also, imply a forced flush if we hit more than
                         * LONG_LINE_MAX characters */

                        if (e - begin >= (ptrdiff_t) LONG_LINE_MAX)
                                eol_found |= EOL_TOO_LONG;
                        if (force_flush && l <= 1)
                                eol_found |= EOL_FORCE_FLUSH;

                        if (eol_found == EOL_NONE) {
                                /* This is just a regular character. Yay. Let's now look for all EOL types again */
                                eol_mask = _EOL_MASK_ALL;
                                e++;
                                l--;
                                continue;
                        }

                        if (FLAGS_SET(eol_found, EOL_FORCE_FLUSH)) {
                                /* This is a forced flush: include the final character in the line and consume
                                 * it, so that we are guaranteed to make progress and terminate. */
                                e++;
                                l--;
                        }
                        /* Otherwise this is an overly long line: break before the current character, it shall
                         * start the next line. */

                        n_drop_extra = 0; /* There's no actual EOL character to eat up */
                } else
                        n_drop_extra = 1;

                /* Check if this is an EOL marker we are looking for */
                if (FLAGS_SET(eol_mask, eol_found)) {
                        /* We hit a new EOL marker. Let's generate a line from this */
                        if (begin)
                                r = pseudo_tty_dispatch_line(pty, begin, e - begin);
                        else
                                r = pseudo_tty_dispatch_line(pty, /* p= */ NULL, /* n= */ 0);
                        if (r < 0)
                                return r;

                        /* Let's drop what we processed from the buffer */
                        assert_se(iovec_reduce(&pty->frontend_read_buffer, (e - (char*) pty->frontend_read_buffer.iov_base) + n_drop_extra));

                        /* Restart with an empty line indicator. */
                        begin = NULL;
                        e = pty->frontend_read_buffer.iov_base;
                        l = pty->frontend_read_buffer.iov_len;

                        /* None of the other EOL types shall be recognized as line breaks until we hit another one of the one we just hit. */
                        pty->eol_mask = eol_mask = (eol_found & (EOL_TOO_LONG|EOL_FORCE_FLUSH)) != 0 ? _EOL_MASK_ALL : (eol_found|EOL_TOO_LONG|EOL_FORCE_FLUSH);
                        continue;
                }

                /* If we hit this EOL marker, but ignored it because it was used in conjunction with another
                 * one, then do honour it if it shows up the next time. */
                eol_mask |= eol_found;

                e++;
                l--;
        }

        return 0;
}

static int pseudo_tty_process_hangup(PseudoTTY *pty, uint32_t revents) {
        assert(pty);

        if (pty->frontend_fd < 0)
                return -ECONNRESET;

        if (FLAGS_SET(revents, EPOLLHUP))
                return -ECONNRESET;

        return 0;
}

void pseudo_tty_add_to_free_queue(PseudoTTY *pty) {
        assert(pty);

        if (pty->in_free_queue)
                return;

        log_debug("Queuing PTY '%s' for removal.", strna(pty->name));

        LIST_PREPEND(free_queue, pty->manager->ptys_free_queue, pty);
        pty->in_free_queue = true;

        /* Trigger the deferred drain of the free queue. We don't free right here since we may be called from
         * within one of this PTY's own I/O callbacks. */
        (void) sd_event_source_set_enabled(pty->manager->ptys_free_queue_event_source, SD_EVENT_ONESHOT);
}

static int io_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        PseudoTTY *pty = ASSERT_PTR(userdata);
        int r;

        assert(s);

        r = 0;
        RET_GATHER(r, pseudo_tty_write(pty));
        RET_GATHER(r, pseudo_tty_read(pty));
        RET_GATHER(r, pseudo_tty_process_hangup(pty, revents));
        RET_GATHER(r, pseudo_tty_process_line(pty, r < 0));
        if (r >= 0)
                r = pseudo_tty_set_events(pty);
        if (r < 0) {
                pseudo_tty_add_to_free_queue(pty);

                if (pty->io_event_source)
                        (void) sd_event_source_set_io_events(pty->io_event_source, 0);

                return r;
        }

        return 0;
}

int pseudo_tty_new(PseudoTTY **ret) {
        assert(ret);

        _cleanup_(pseudo_tty_freep) PseudoTTY *pty = new(PseudoTTY, 1);
        if (!pty)
                return -ENOMEM;

        *pty = (PseudoTTY) {
                .frontend_type = _FRONTEND_TYPE_INVALID,
                .backend_type = _BACKEND_TYPE_INVALID,
                .frontend_fd = -EBADF,
                .backend_fd = -EBADF,
                .pin_fd = -EBADF,
                .eol_mask = _EOL_MASK_ALL,
                .owner_pidref = PIDREF_NULL,
                .owner_uid = UID_INVALID,
                .owner_gid = GID_INVALID,
        };

        *ret = TAKE_PTR(pty);
        return 0;
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                pseudo_tty_hashops,
                char,
                string_hash_func,
                string_compare_func,
                PseudoTTY,
                pseudo_tty_free);

int pseudo_tty_link(PseudoTTY *pty, Manager *m) {
        int r;

        assert(pty);
        assert(m);
        assert(pty->name);

        r = hashmap_ensure_put(&m->ptys, &pseudo_tty_hashops, pty->name, pty);
        if (r < 0)
                return r;

        pty->manager = m;
        return 0;
}

int pseudo_tty_watch_frontend_fd(PseudoTTY *pty, sd_event *event) {
        int r;
        assert(pty);

        if (pty->frontend_fd < 0)
                return 0;

        r = fd_nonblock(pty->frontend_fd, true);
        if (r < 0)
                return log_error_errno(r, "Failed to mark pty fd is non-blocking: %m");

        r = sd_event_add_io(event, &pty->io_event_source, pty->frontend_fd, /* events= */ 0, io_callback, pty);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate IO event source: %m");

        r = pseudo_tty_set_events(pty);
        if (r < 0)
                return log_error_errno(r, "Failed to set IO events to watch for: %m");

        return 0;
}

static int backend_node_inotify_callback(sd_event_source *s, const struct inotify_event *event, void *userdata) {
        PseudoTTY *pty = ASSERT_PTR(userdata);

        assert(s);

        /* The backend ('slave') device node was removed from /dev/pts/, which the kernel does once the last
         * frontend ('master') reference is gone, i.e. the PTY has been destroyed. This is our hang-up signal
         * for the FRONTEND_TAKE case: there we handed the frontend fd to the client and closed our own copy,
         * so there is no fd left on which we'd see EPOLLHUP. Tear the PTY object down, just like io_callback()
         * does when it sees a hangup on a frontend fd we do keep.
         *
         * Verify the node is actually gone before acting. */

        struct stat st;
        if (fstat(pty->pin_fd, &st) < 0)
                log_debug_errno(errno, "Failed to fstat() backend inode, assuming pty is dead: %m");
        else if (st.st_nlink > 0) {
                log_debug("Got IN_DELETE_SELF event, but inode is still there, ignoring.");
                return 0;
        }

        pty->backend_inotify_event_source = sd_event_source_disable_unref(pty->backend_inotify_event_source);

        /* If a vhangup is queued, then let the child process exit cause the clean-up */
        if (pty->vhangup_event_source)
                return 0;

        pseudo_tty_add_to_free_queue(pty);
        return 0;
}

int pseudo_tty_watch_backend_node(PseudoTTY *pty, sd_event *event) {
        int r;

        assert(pty);
        assert(event);

        if (pty->pin_fd < 0)
                return 0;

        /* Watch the backend device node for removal via the pinning O_PATH fd we keep around. */
        r = sd_event_add_inotify_fd(event, &pty->backend_inotify_event_source, pty->pin_fd, IN_DELETE_SELF, backend_node_inotify_callback, pty);
        if (r < 0)
                return log_error_errno(r, "Failed to watch PTY backend node for removal: %m");

        return 0;
}

int pseudo_tty_track_buffer_to_json(PseudoTTY *pty, size_t n_lines, sd_json_variant **ret) {
        int r;

        assert(pty);
        assert(ret);

        size_t n = MIN(n_lines, pty->track_buffer_allocated_lines);
        if (n <= 0) {
                *ret = NULL;
                return 0;
        }

        /* NB: new0() so that the array is NUL terminated even if every slot in the window turns out to
         * be empty and the loop below never writes anything */
        _cleanup_free_ const char **array = new0(const char*, n + 1);
        if (!array)
                return -ENOMEM;

        size_t start = pty->track_buffer_next_line + pty->track_buffer_allocated_lines - n;

        /* track_buffer_next_line points at the oldest line of the (always fully populated) ring; return the
         * most recent n lines, in the order they were logged */
        for (size_t i = 0, j = 0; i < n; i++) {
                char *line = pty->track_buffer[(start + i) % pty->track_buffer_allocated_lines];
                if (!line) /* when the buffer size is hit we might NULL out some older lines, skip over them
                            * here */
                        continue;

                array[j++] = line;
                array[j] = NULL;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *l = NULL;
        r = sd_json_variant_new_array_strv(&l, (char**) array);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(l);
        return 0;
}

static int vhangup_callback(sd_event_source *s, const siginfo_t *si, void *userdata) {
        PseudoTTY *pty = ASSERT_PTR(userdata);
        int r;

        r = varlink_many_reply(pty->vhangup_links, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to issue hangup method call replies, ignoring: %m");

        pseudo_tty_add_to_free_queue(pty);
        return 0;
}

int pseudo_tty_vhangup(PseudoTTY *pty) {
        int r;

        assert(pty);

        if (pty->vhangup_event_source)
                return 0;

        log_debug("Hanging up PTY '%s'.", strna(pty->name));

        if (pty->pin_fd < 0)
                return -ENOTTY;

        int pin_fd = pty->pin_fd;

        /* NB: until the child event source takes ownership of the child below, an error path kills and
         * reaps it, so that it doesn't linger as zombie */
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork_full(
                        "(vhangup)",
                        /* stdio_fds= */ NULL,
                        /* except_fds= */ &pin_fd,
                        /* n_except_fds= */ 1,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGKILL,
                        /* ret= */ &pidref);
        if (r < 0)
                return log_error_errno(r, "Failed to fork off vhangup() child: %m");
        if (r == 0) {
                _cleanup_close_ int fd = fd_reopen(pin_fd, O_RDWR|O_CLOEXEC|O_NOCTTY);
                if (fd < 0)
                        goto child_fail;

                pin_fd = safe_close(pin_fd);

                if (terminal_vhangup_fd(fd) < 0)
                        goto child_fail;

                fd = safe_close(fd);
                _exit(EXIT_SUCCESS);

        child_fail:
                _exit(EXIT_FAILURE);
        }

        /* Watch the child before we drop our fds and I/O event source: if we can't, we leave the pty as it
         * was, so that the usual hangup paths remain in effect (rather than leaving the pty around without
         * anything ever queuing it for removal). */
        r = event_add_child_pidref(
                        pty->manager->event,
                        &pty->vhangup_event_source,
                        &pidref,
                        WEXITED,
                        vhangup_callback,
                        pty);
        if (r < 0)
                return log_error_errno(r, "Failed to watch vhangup() child: %m");

        r = sd_event_source_set_child_process_own(pty->vhangup_event_source, true);
        if (r < 0) {
                pty->vhangup_event_source = sd_event_source_disable_unref(pty->vhangup_event_source);
                return log_error_errno(r, "Failed to pass ownership of vhangup() child to event source: %m");
        }

        /* The event source owns the child now, hence disarm the cleanup handler */
        pidref_done(&pidref);

        pty->io_event_source = sd_event_source_disable_unref(pty->io_event_source);
        pty->frontend_fd = safe_close(pty->frontend_fd);
        pty->backend_fd = safe_close(pty->backend_fd);
        pty->pin_fd = safe_close(pty->pin_fd);

        return 0;
}

static const char* const frontend_type_table[_FRONTEND_TYPE_MAX] = {
        [FRONTEND_TAKE] = "take",
        [FRONTEND_NULL] = "null",
        [FRONTEND_LOG]  = "log",
};
DEFINE_STRING_TABLE_LOOKUP(frontend_type, FrontendType);

static const char* const backend_type_table[_BACKEND_TYPE_MAX] = {
        [BACKEND_TAKE]  = "take",
        [BACKEND_SHELL] = "shell",
};
DEFINE_STRING_TABLE_LOOKUP(backend_type, BackendType);
