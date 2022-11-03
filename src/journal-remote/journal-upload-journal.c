/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <curl/curl.h>
#include <stdbool.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "journal-upload.h"
#include "log.h"
#include "string-util.h"
#include "utf8.h"
#include "util.h"

/**
 * Write up to size bytes to buf. Return negative on error, and number of
 * bytes written otherwise. The last case is a kind of an error too.
 */
static ssize_t write_entry(char *buf, size_t size, Uploader *u) {
        int r;
        size_t pos = 0;

        assert(size <= SSIZE_MAX);

        for (;;) {

                switch (u->entry_state) {
                case ENTRY_CURSOR: {
                        u->current_cursor = mfree(u->current_cursor);

                        r = sd_journal_get_cursor(u->journal, &u->current_cursor);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get cursor: %m");

                        r = snprintf(buf + pos, size - pos,
                                     "__CURSOR=%s\n", u->current_cursor);
                        assert(r >= 0);
                        if ((size_t) r > size - pos)
                                /* not enough space */
                                return pos;

                        u->entry_state++;

                        if (pos + r == size) {
                                /* exactly one character short, but we don't need it */
                                buf[size - 1] = '\n';
                                return size;
                        }

                        pos += r;
                }
                        _fallthrough_;
                case ENTRY_REALTIME: {
                        usec_t realtime;

                        r = sd_journal_get_realtime_usec(u->journal, &realtime);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get realtime timestamp: %m");

                        r = snprintf(buf + pos, size - pos,
                                     "__REALTIME_TIMESTAMP="USEC_FMT"\n", realtime);
                        assert(r >= 0);
                        if ((size_t) r > size - pos)
                                /* not enough space */
                                return pos;

                        u->entry_state++;

                        if (r + pos == size) {
                                /* exactly one character short, but we don't need it */
                                buf[size - 1] = '\n';
                                return size;
                        }

                        pos += r;
                }
                        _fallthrough_;
                case ENTRY_MONOTONIC: {
                        usec_t monotonic;
                        sd_id128_t boot_id;

                        r = sd_journal_get_monotonic_usec(u->journal, &monotonic, &boot_id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get monotonic timestamp: %m");

                        r = snprintf(buf + pos, size - pos,
                                     "__MONOTONIC_TIMESTAMP="USEC_FMT"\n", monotonic);
                        assert(r >= 0);
                        if ((size_t) r > size - pos)
                                /* not enough space */
                                return pos;

                        u->entry_state++;

                        if (r + pos == size) {
                                /* exactly one character short, but we don't need it */
                                buf[size - 1] = '\n';
                                return size;
                        }

                        pos += r;
                }
                        _fallthrough_;
                case ENTRY_BOOT_ID: {
                        sd_id128_t boot_id;

                        r = sd_journal_get_monotonic_usec(u->journal, NULL, &boot_id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get monotonic timestamp: %m");

                        r = snprintf(buf + pos, size - pos,
                                     "_BOOT_ID=%s\n", SD_ID128_TO_STRING(boot_id));
                        assert(r >= 0);
                        if ((size_t) r > size - pos)
                                /* not enough space */
                                return pos;

                        u->entry_state++;

                        if (r + pos == size) {
                                /* exactly one character short, but we don't need it */
                                buf[size - 1] = '\n';
                                return size;
                        }

                        pos += r;
                }
                        _fallthrough_;
                case ENTRY_NEW_FIELD: {
                        u->field_pos = 0;

                        r = sd_journal_enumerate_data(u->journal,
                                                      &u->field_data,
                                                      &u->field_length);
                        if (r < 0)
                                return log_error_errno(r, "Failed to move to next field in entry: %m");
                        else if (r == 0) {
                                u->entry_state = ENTRY_OUTRO;
                                continue;
                        }

                        /* We already printed the boot id from the data in
                         * the header, hence let's suppress it here */
                        if (memory_startswith(u->field_data, u->field_length, "_BOOT_ID="))
                                continue;

                        if (!utf8_is_printable_newline(u->field_data, u->field_length, false)) {
                                u->entry_state = ENTRY_BINARY_FIELD_START;
                                continue;
                        }

                        u->entry_state++;
                }
                        _fallthrough_;
                case ENTRY_TEXT_FIELD:
                case ENTRY_BINARY_FIELD: {
                        bool done;
                        size_t tocopy;

                        done = size - pos > u->field_length - u->field_pos;
                        if (done)
                                tocopy = u->field_length - u->field_pos;
                        else
                                tocopy = size - pos;

                        memcpy(buf + pos,
                               (char*) u->field_data + u->field_pos,
                               tocopy);

                        if (done) {
                                buf[pos + tocopy] = '\n';
                                pos += tocopy + 1;
                                u->entry_state = ENTRY_NEW_FIELD;
                                continue;
                        } else {
                                u->field_pos += tocopy;
                                return size;
                        }
                }

                case ENTRY_BINARY_FIELD_START: {
                        const char *c;
                        size_t len;

                        c = memchr(u->field_data, '=', u->field_length);
                        if (!c || c == u->field_data)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid field.");

                        len = c - (const char*)u->field_data;

                        /* need space for label + '\n' */
                        if (size - pos < len + 1)
                                return pos;

                        memcpy(buf + pos, u->field_data, len);
                        buf[pos + len] = '\n';
                        pos += len + 1;

                        u->field_pos = len + 1;
                        u->entry_state++;
                }
                        _fallthrough_;
                case ENTRY_BINARY_FIELD_SIZE: {
                        uint64_t le64;

                        /* need space for uint64_t */
                        if (size - pos < 8)
                                return pos;

                        le64 = htole64(u->field_length - u->field_pos);
                        memcpy(buf + pos, &le64, 8);
                        pos += 8;

                        u->entry_state++;
                        continue;
                }

                case ENTRY_OUTRO:
                        /* need space for '\n' */
                        if (size - pos < 1)
                                return pos;

                        buf[pos++] = '\n';
                        u->entry_state++;
                        u->entries_sent++;

                        return pos;

                default:
                        assert_not_reached();
                }
        }
        assert_not_reached();
}

static void check_update_watchdog(Uploader *u) {
        usec_t after;
        usec_t elapsed_time;

        if (u->watchdog_usec <= 0)
                return;

        after = now(CLOCK_MONOTONIC);
        elapsed_time = usec_sub_unsigned(after, u->watchdog_timestamp);
        if (elapsed_time > u->watchdog_usec / 2) {
                log_debug("Update watchdog timer");
                sd_notify(false, "WATCHDOG=1");
                u->watchdog_timestamp = after;
        }
}

static size_t journal_input_callback(void *buf, size_t size, size_t nmemb, void *userp) {
        Uploader *u = ASSERT_PTR(userp);
        int r;
        sd_journal *j;
        size_t filled = 0;
        ssize_t w;

        assert(nmemb <= SSIZE_MAX / size);

        check_update_watchdog(u);

        j = u->journal;

        while (j && filled < size * nmemb) {
                if (u->entry_state == ENTRY_DONE) {
                        r = sd_journal_next(j);
                        if (r < 0) {
                                log_error_errno(r, "Failed to move to next entry in journal: %m");
                                return CURL_READFUNC_ABORT;
                        } else if (r == 0) {
                                if (u->input_event)
                                        log_debug("No more entries, waiting for journal.");
                                else {
                                        log_info("No more entries, closing journal.");
                                        close_journal_input(u);
                                }

                                u->uploading = false;

                                break;
                        }

                        u->entry_state = ENTRY_CURSOR;
                }

                w = write_entry((char*)buf + filled, size * nmemb - filled, u);
                if (w < 0)
                        return CURL_READFUNC_ABORT;
                filled += w;

                if (filled == 0) {
                        log_error("Buffer space is too small to write entry.");
                        return CURL_READFUNC_ABORT;
                } else if (u->entry_state != ENTRY_DONE)
                        /* This means that all available space was used up */
                        break;

                log_debug("Entry %zu (%s) has been uploaded.",
                          u->entries_sent, u->current_cursor);
        }

        return filled;
}

void close_journal_input(Uploader *u) {
        assert(u);

        if (u->journal) {
                log_debug("Closing journal input.");

                sd_journal_close(u->journal);
                u->journal = NULL;
        }
        u->timeout = 0;
}

static int process_journal_input(Uploader *u, int skip) {
        int r;

        if (u->uploading)
                return 0;

        r = sd_journal_next_skip(u->journal, skip);
        if (r < 0)
                return log_error_errno(r, "Failed to skip to next entry: %m");
        else if (r < skip)
                return 0;

        /* have data */
        u->entry_state = ENTRY_CURSOR;
        return start_upload(u, journal_input_callback, u);
}

int check_journal_input(Uploader *u) {
        if (u->input_event) {
                int r;

                r = sd_journal_process(u->journal);
                if (r < 0) {
                        log_error_errno(r, "Failed to process journal: %m");
                        close_journal_input(u);
                        return r;
                }

                if (r == SD_JOURNAL_NOP)
                        return 0;
        }

        return process_journal_input(u, 1);
}

static int dispatch_journal_input(sd_event_source *event,
                                  int fd,
                                  uint32_t revents,
                                  void *userp) {
        Uploader *u = ASSERT_PTR(userp);

        if (u->uploading)
                return 0;

        log_debug("Detected journal input, checking for new data.");
        return check_journal_input(u);
}

int open_journal_for_upload(Uploader *u,
                            sd_journal *j,
                            const char *cursor,
                            bool after_cursor,
                            bool follow) {
        int fd, r, events;

        u->journal = j;

        sd_journal_set_data_threshold(j, 0);

        if (follow) {
                fd = sd_journal_get_fd(j);
                if (fd < 0)
                        return log_error_errno(fd, "sd_journal_get_fd failed: %m");

                events = sd_journal_get_events(j);

                r = sd_journal_reliable_fd(j);
                assert(r >= 0);
                if (r > 0)
                        u->timeout = -1;
                else
                        u->timeout = JOURNAL_UPLOAD_POLL_TIMEOUT;

                r = sd_event_add_io(u->events, &u->input_event,
                                    fd, events, dispatch_journal_input, u);
                if (r < 0)
                        return log_error_errno(r, "Failed to register input event: %m");

                log_debug("Listening for journal events on fd:%d, timeout %d",
                          fd, u->timeout == UINT64_MAX ? -1 : (int) u->timeout);
        } else
                log_debug("Not listening for journal events.");

        if (cursor) {
                r = sd_journal_seek_cursor(j, cursor);
                if (r < 0)
                        return log_error_errno(r, "Failed to seek to cursor %s: %m",
                                               cursor);
        }

        return process_journal_input(u, !!after_cursor);
}
