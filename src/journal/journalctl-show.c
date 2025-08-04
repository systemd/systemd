/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-journal.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "fileio.h"
#include "journalctl.h"
#include "journalctl-filter.h"
#include "journalctl-show.h"
#include "journalctl-util.h"
#include "journalctl-varlink.h"
#include "log.h"
#include "logs-show.h"
#include "output-mode.h"
#include "pager.h"
#include "string-util.h"
#include "terminal-util.h"
#include "time-util.h"

#define PROCESS_INOTIFY_INTERVAL 1024   /* Every 1024 messages processed */

typedef struct Context {
        sd_journal *journal;
        bool has_cursor;
        bool need_seek;
        bool since_seeked;
        bool until_safe;
        bool ellipsized;
        bool previous_boot_id_valid;
        sd_id128_t previous_boot_id;
        sd_id128_t previous_boot_id_output;
        dual_timestamp previous_ts_output;
        sd_event *event;
        sd_varlink *synchronize_varlink;
} Context;

static void context_done(Context *c) {
        assert(c);

        sd_varlink_flush_close_unref(c->synchronize_varlink);
        sd_event_unref(c->event);
        sd_journal_close(c->journal);
}

static int seek_journal(Context *c) {
        sd_journal *j = ASSERT_PTR(ASSERT_PTR(c)->journal);
        _cleanup_free_ char *cursor_from_file = NULL;
        const char *cursor = NULL;
        bool after_cursor = false;
        int r;

        if (arg_cursor || arg_after_cursor) {
                assert(!!arg_cursor != !!arg_after_cursor);

                cursor = arg_cursor ?: arg_after_cursor;
                after_cursor = arg_after_cursor;

        } else if (arg_cursor_file) {
                r = read_one_line_file(arg_cursor_file, &cursor_from_file);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to read cursor file %s: %m", arg_cursor_file);
                if (r > 0) {
                        cursor = cursor_from_file;
                        after_cursor = true;
                }
        }

        if (cursor) {
                c->has_cursor = true;

                r = sd_journal_seek_cursor(j, cursor);
                if (r < 0)
                        return log_error_errno(r, "Failed to seek to cursor: %m");

                r = sd_journal_step_one(j, !arg_reverse);
                if (r < 0)
                        return log_error_errno(r, "Failed to iterate through journal: %m");

                if (after_cursor && r > 0) {
                        /* With --after-cursor=/--cursor-file= we want to skip the first entry only if it's
                         * the entry the cursor is pointing at, otherwise, if some journal filters are used,
                         * we might skip the first entry of the filter match, which leads to unexpectedly
                         * missing journal entries. */
                        int k;

                        k = sd_journal_test_cursor(j, cursor);
                        if (k < 0)
                                return log_error_errno(k, "Failed to test cursor against current entry: %m");
                        if (k > 0)
                                /* Current entry matches the one our cursor is pointing at, so let's try
                                 * to advance the next entry. */
                                r = sd_journal_step_one(j, !arg_reverse);
                }

                if (r == 0 && !arg_follow)
                        /* We couldn't find the next entry after the cursor. */
                        arg_lines = 0;

        } else if (arg_reverse || arg_lines_needs_seek_end()) {
                /* If --reverse and/or --lines=N are specified, things get a little tricky. First we seek to
                 * the place of --until if specified, otherwise seek to tail. Then, if --reverse is
                 * specified, we search backwards and let the output counter in show() handle --lines for us.
                 * If --reverse is unspecified, we just jump backwards arg_lines and search afterwards from
                 * there. */

                if (arg_until_set) {
                        r = sd_journal_seek_realtime_usec(j, arg_until);
                        if (r < 0)
                                return log_error_errno(r, "Failed to seek to date: %m");
                } else {
                        r = sd_journal_seek_tail(j);
                        if (r < 0)
                                return log_error_errno(r, "Failed to seek to tail: %m");
                }

                if (arg_reverse) {
                        r = sd_journal_previous(j);
                        c->until_safe = true; /* can't possibly go beyond --until= if --reverse */

                } else { /* arg_lines_needs_seek_end() */
                        r = sd_journal_previous_skip(j, arg_lines);
                        c->until_safe = r >= arg_lines; /* We have enough lines to output before --until= is hit.
                                                           No need to check timestamp of each journal entry */
                }

        } else if (arg_since_set) {
                /* This is placed after arg_reverse and arg_lines. If --since is used without
                 * both, we seek to the place of --since and search afterwards from there.
                 * If used with --reverse or --lines, we seek to the tail first and check if
                 * the entry is within the range of --since later. */

                r = sd_journal_seek_realtime_usec(j, arg_since);
                if (r < 0)
                        return log_error_errno(r, "Failed to seek to date: %m");
                c->since_seeked = true;

                r = sd_journal_next(j);

        } else {
                r = sd_journal_seek_head(j);
                if (r < 0)
                        return log_error_errno(r, "Failed to seek to head: %m");

                r = sd_journal_next(j);
        }
        if (r < 0)
                return log_error_errno(r, "Failed to iterate through journal: %m");
        if (r == 0)
                c->need_seek = true;

        return 0;
}

static int show(Context *c) {
        sd_journal *j = ASSERT_PTR(ASSERT_PTR(c)->journal);
        int r, n_shown = 0;

        OutputFlags flags =
                arg_all * OUTPUT_SHOW_ALL |
                arg_full * OUTPUT_FULL_WIDTH |
                colors_enabled() * OUTPUT_COLOR |
                arg_catalog * OUTPUT_CATALOG |
                arg_utc * OUTPUT_UTC |
                arg_truncate_newline * OUTPUT_TRUNCATE_NEWLINE |
                arg_no_hostname * OUTPUT_NO_HOSTNAME;

        while (arg_lines < 0 || n_shown < arg_lines || arg_follow) {
                size_t highlight[2] = {};

                if (c->need_seek) {
                        r = sd_journal_step_one(j, !arg_reverse);
                        if (r < 0)
                                return log_error_errno(r, "Failed to iterate through journal: %m");
                        if (r == 0)
                                break;
                }

                if (arg_until_set && !c->until_safe) {
                        /* If --lines= is set, we usually rely on the n_shown to tell us when to stop.
                         * However, in the case where we may have less than --lines= to output let's check
                         * whether the individual entries are in range. */

                        usec_t usec;

                        r = sd_journal_get_realtime_usec(j, &usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine timestamp: %m");
                        if (usec > arg_until)
                                break;
                }

                if (arg_since_set && (arg_reverse || !c->since_seeked)) {
                        usec_t usec;

                        r = sd_journal_get_realtime_usec(j, &usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine timestamp: %m");

                        if (usec < arg_since) {
                                if (arg_reverse)
                                        break; /* Reached the earliest entry */

                                /* arg_lines >= 0 (!since_seeked):
                                 * We jumped arg_lines back and it seems to be too much */
                                r = sd_journal_seek_realtime_usec(j, arg_since);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to seek to date: %m");
                                c->since_seeked = true;

                                /* We just jumped forward, meaning there might suddenly be less than
                                 * --lines= to show within the --until= range, hence keep a close eye on
                                 * timestamps from now on. */
                                c->until_safe = false;

                                c->need_seek = true;
                                continue;
                        }
                        c->since_seeked = true; /* We're surely within the range of --since now */
                }

                if (!arg_merge && !arg_quiet) {
                        sd_id128_t boot_id;

                        r = sd_journal_get_monotonic_usec(j, NULL, &boot_id);
                        if (r >= 0) {
                                if (c->previous_boot_id_valid &&
                                    !sd_id128_equal(boot_id, c->previous_boot_id))
                                        printf("%s-- Boot "SD_ID128_FORMAT_STR" --%s\n",
                                               ansi_highlight(), SD_ID128_FORMAT_VAL(boot_id), ansi_normal());

                                c->previous_boot_id = boot_id;
                                c->previous_boot_id_valid = true;
                        }
                }

                if (arg_compiled_pattern) {
                        const void *message;
                        size_t len;

                        r = sd_journal_get_data(j, "MESSAGE", &message, &len);
                        if (r < 0) {
                                if (r == -ENOENT) {
                                        /* We will skip some entries forward, meaning there might suddenly
                                         * be less than --lines= to show within the --until= range, hence
                                         * keep a close eye on timestamps from now on. */
                                        if (!arg_reverse)
                                                c->until_safe = false;

                                        c->need_seek = true;
                                        continue;
                                }

                                return log_error_errno(r, "Failed to get MESSAGE field: %m");
                        }

                        assert_se(message = startswith(message, "MESSAGE="));

                        r = pattern_matches_and_log(arg_compiled_pattern, message,
                                                    len - strlen("MESSAGE="), highlight);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                /* We will skip some entries forward, meaning there might suddenly
                                 * be less than --lines= to show within the --until= range, hence
                                 * keep a close eye on timestamps from now on. */
                                if (!arg_reverse)
                                        c->until_safe = false;

                                c->need_seek = true;
                                continue;
                        }
                }

                r = show_journal_entry(stdout, j, arg_output, 0, flags,
                                       arg_output_fields, highlight, &c->ellipsized,
                                       &c->previous_ts_output, &c->previous_boot_id_output);
                c->need_seek = true;
                if (r == -EADDRNOTAVAIL)
                        break;
                if (r < 0)
                        return r;

                n_shown++;

                /* If journalctl take a long time to process messages, and during that time journal file
                 * rotation occurs, a journalctl client will keep those rotated files open until it calls
                 * sd_journal_process(), which typically happens as a result of calling sd_journal_wait() below
                 * in the "following" case.  By periodically calling sd_journal_process() during the processing
                 * loop we shrink the window of time a client instance has open file descriptors for rotated
                 * (deleted) journal files. */
                if ((n_shown % PROCESS_INOTIFY_INTERVAL) == 0) {
                        r = sd_journal_process(j);
                        if (r < 0)
                                return log_error_errno(r, "Failed to process inotify events: %m");
                }
        }

        return n_shown;
}

static int show_and_fflush(Context *c) {
        int r;

        assert(c);

        r = show(c);
        if (r < 0)
                return sd_event_exit(c->event, r);

        fflush(stdout);
        return 0;
}

static int on_journal_event(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(s);

        r = sd_journal_process(c->journal);
        if (r < 0) {
                log_error_errno(r, "Failed to process journal events: %m");
                return sd_event_exit(c->event, r);
        }

        return show_and_fflush(c);
}

static int on_first_event(sd_event_source *s, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(s);

        r = show_and_fflush(c);
        if (r < 0)
                return r;

        if (arg_follow && !arg_reverse && !c->has_cursor && !arg_since_set) {
                r = sd_journal_get_cursor(c->journal, /* ret_cursor= */ NULL);
                if (r == -EADDRNOTAVAIL) {
                        /* If we shall operate in --follow mode, and we are unable to get a cursor after
                         * doing our first round of output, then this means there was no data to show
                         * whatsoever, and we hence have no stable position on any line at all. This means,
                         * when we get notified about changes, we shouldn't try to position the cursor at the
                         * end of the logs anymore, but at the beginning, since anything showing up from now
                         * that matches our filters is good now. Hence, simply disable the effect of --lines=
                         * now. */

                        r = sd_journal_seek_head(c->journal);
                        if (r < 0)
                                return log_error_errno(r, "Failed to seek to head: %m");

                        c->need_seek = true;

                } else if (r < 0)
                        return log_error_errno(r, "Failed to get cursor: %m");
        }

        (void) sd_notify(/* unset_environment= */ false, "READY=1");
        return 0;
}

static int on_synchronize_reply(
                sd_varlink *vl,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        Context *c = ASSERT_PTR(userdata);
        int r;

        assert(vl);

        if (error_id) {
                log_warning("Failed to synchronize on Journal, ignoring: %s", error_id);
                (void) sd_notifyf(/* unset_environment= */ false, "VARLINKERROR=%s", error_id);
        }

        r = show_and_fflush(c);
        if (r < 0)
                return r;

        return sd_event_exit(c->event, EXIT_SUCCESS);
}

static int on_signal(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        Context *c = ASSERT_PTR(userdata);
        int r = 0;

        assert(s);
        assert(si);
        assert(IN_SET(si->ssi_signo, SIGTERM, SIGINT));

        if (!arg_synchronize_on_exit)
                goto finish;

        if (c->synchronize_varlink) /* Already pending? Then exit immediately, so that user can cancel the sync */
                goto finish;

        r = varlink_connect_journal(&vl);
        if (r < 0) {
                log_error_errno(r, "Failed to connect to Journal Varlink IPC interface, skipping synchronization: %m");
                goto finish;
        }

        /* Set a low priority on the idle event handler, so that we show any log messages first */
        r = sd_varlink_attach_event(vl, c->event, SD_EVENT_PRIORITY_IDLE);
        if (r < 0) {
                log_warning_errno(r, "Failed to attach Varlink connection to event loop: %m");
                goto finish;
        }

        r = sd_varlink_bind_reply(vl, on_synchronize_reply);
        if (r < 0) {
                log_warning_errno(r, "Failed to bind synchronization reply: %m");
                goto finish;
        }

        (void) sd_varlink_set_userdata(vl, c);

        r = sd_varlink_invokebo(
                        vl,
                        "io.systemd.Journal.Synchronize",
                        SD_JSON_BUILD_PAIR_BOOLEAN("offline", false));
        if (r < 0) {
                log_warning_errno(r, "Failed to issue synchronization request: %m");
                goto finish;
        }

        c->synchronize_varlink = TAKE_PTR(vl);
        return 0;

finish:
        return sd_event_exit(c->event, r);
}

static int setup_event(Context *c, int fd) {
        int r;

        assert(arg_follow);
        assert(c);
        assert(fd >= 0);
        assert(!c->event);

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        r = sd_event_default(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate sd_event object: %m");

        (void) sd_event_add_signal(e, /* ret= */ NULL, SIGTERM | SD_EVENT_SIGNAL_PROCMASK, on_signal, c);
        (void) sd_event_add_signal(e, /* ret= */ NULL, SIGINT | SD_EVENT_SIGNAL_PROCMASK, on_signal, c);

        r = sd_event_add_io(e, /* ret = */ NULL, fd, EPOLLIN, &on_journal_event, c);
        if (r < 0)
                return log_error_errno(r, "Failed to add io event source for journal: %m");

        /* Also keeps an eye on STDOUT, and exits as soon as we see a POLLHUP on that, i.e. when it is closed. */
        r = sd_event_add_io(e, /* ret = */ NULL, STDOUT_FILENO, EPOLLHUP|EPOLLERR, /* callback = */ NULL, /* userdata = */ NULL);
        if (r == -EPERM)
                /* Installing an epoll watch on a regular file doesn't work and fails with EPERM. Which is
                 * totally OK, handle it gracefully. epoll_ctl() documents EPERM as the error returned when
                 * the specified fd doesn't support epoll, hence it's safe to check for that. */
                log_debug_errno(r, "Unable to install EPOLLHUP watch on stderr, not watching for hangups.");
        else if (r < 0)
                return log_error_errno(r, "Failed to add io event source for stdout: %m");

        if (arg_lines != 0 || arg_since_set) {
                r = sd_event_add_defer(e, NULL, on_first_event, c);
                if (r < 0)
                        return log_error_errno(r, "Failed to add defer event source: %m");
        }

        c->event = TAKE_PTR(e);
        return 0;
}

static int update_cursor(sd_journal *j) {
        _cleanup_free_ char *cursor = NULL;
        int r;

        assert(j);

        if (!arg_show_cursor && !arg_cursor_file)
                return 0;

        r = sd_journal_get_cursor(j, &cursor);
        if (r == -EADDRNOTAVAIL)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to get cursor: %m");

        if (arg_show_cursor)
                printf("-- cursor: %s\n", cursor);

        if (arg_cursor_file) {
                r = write_string_file(arg_cursor_file, cursor, WRITE_STRING_FILE_CREATE | WRITE_STRING_FILE_ATOMIC);
                if (r < 0)
                        return log_error_errno(r, "Failed to write new cursor to %s: %m", arg_cursor_file);
        }

        return 0;
}

int action_show(char **matches) {
        _cleanup_(context_done) Context c = {};
        int n_shown, r, poll_fd = -EBADF;

        assert(arg_action == ACTION_SHOW);

        (void) signal(SIGWINCH, columns_lines_cache_reset);

        r = acquire_journal(&c.journal);
        if (r < 0)
                return r;

        if (!journal_boot_has_effect(c.journal))
                return arg_compiled_pattern ? -ENOENT : 0;

        r = add_filters(c.journal, matches);
        if (r < 0)
                return r;

        r = seek_journal(&c);
        if (r < 0)
                return r;

        /* Opening the fd now means the first sd_journal_wait() will actually wait */
        if (arg_follow) {
                poll_fd = sd_journal_get_fd(c.journal);
                if (poll_fd == -EMFILE) {
                        log_warning_errno(poll_fd, "Insufficient watch descriptors available. Reverting to -n.");
                        arg_follow = false;
                } else if (poll_fd == -EMEDIUMTYPE)
                        return log_error_errno(poll_fd, "The --follow switch is not supported in conjunction with reading from STDIN.");
                else if (poll_fd < 0)
                        return log_error_errno(poll_fd, "Failed to get journal fd: %m");
        }

        if (!arg_follow)
                pager_open(arg_pager_flags);

        if (!arg_quiet && (arg_lines != 0 || arg_follow) && DEBUG_LOGGING) {
                usec_t start, end;
                char start_buf[FORMAT_TIMESTAMP_MAX], end_buf[FORMAT_TIMESTAMP_MAX];

                r = sd_journal_get_cutoff_realtime_usec(c.journal, &start, &end);
                if (r < 0)
                        return log_error_errno(r, "Failed to get cutoff: %m");
                if (r > 0) {
                        if (arg_follow)
                                printf("-- Journal begins at %s. --\n",
                                       format_timestamp_maybe_utc(start_buf, sizeof(start_buf), start));
                        else
                                printf("-- Journal begins at %s, ends at %s. --\n",
                                       format_timestamp_maybe_utc(start_buf, sizeof(start_buf), start),
                                       format_timestamp_maybe_utc(end_buf, sizeof(end_buf), end));
                }
        }

        if (arg_follow) {
                assert(poll_fd >= 0);

                r = setup_event(&c, poll_fd);
                if (r < 0)
                        return r;

                r = sd_event_loop(c.event);
                if (r < 0)
                        return r;

                r = update_cursor(c.journal);
                if (r < 0)
                        return r;

                return 0;
        }

        (void) sd_notify(/* unset_environment= */ false, "READY=1");

        r = show(&c);
        if (r < 0)
                return r;
        n_shown = r;

        if (n_shown == 0 && !arg_quiet)
                printf("-- No entries --\n");

        r = update_cursor(c.journal);
        if (r < 0)
                return r;

        if (arg_compiled_pattern && n_shown == 0)
                /* --grep was used, no error was thrown, but the pattern didn't
                 * match anything. Let's mimic grep's behavior here and return
                 * a non-zero exit code, so journalctl --grep can be used
                 * in scripts and such */
                return -ENOENT;

        return 0;
}
