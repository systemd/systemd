/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "device-util.h"
#include "escape.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "iovec-util.h"
#include "journal-internal.h"
#include "journald-kmsg.h"
#include "journald-server.h"
#include "journald-syslog.h"
#include "log.h"
#include "parse-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "string-util.h"

void server_forward_kmsg(
                Server *s,
                int priority,
                const char *identifier,
                const char *message,
                const struct ucred *ucred) {

        _cleanup_free_ char *ident_buf = NULL;
        struct iovec iovec[5];
        char header_priority[DECIMAL_STR_MAX(priority) + 3],
             header_pid[STRLEN("[]: ") + DECIMAL_STR_MAX(pid_t) + 1];
        size_t n = 0;

        assert(s);
        assert(priority >= 0);
        assert(priority <= 999);
        assert(message);

        if (_unlikely_(LOG_PRI(priority) > s->max_level_kmsg))
                return;

        if (_unlikely_(s->dev_kmsg_fd < 0))
                return;

        /* Never allow messages with kernel facility to be written to
         * kmsg, regardless where the data comes from. */
        priority = syslog_fixup_facility(priority);

        /* First: priority field */
        xsprintf(header_priority, "<%i>", priority);
        iovec[n++] = IOVEC_MAKE_STRING(header_priority);

        /* Second: identifier and PID */
        if (ucred) {
                if (!identifier) {
                        (void) pid_get_comm(ucred->pid, &ident_buf);
                        identifier = ident_buf;
                }

                if (identifier)
                        iovec[n++] = IOVEC_MAKE_STRING(identifier);

                xsprintf(header_pid, "["PID_FMT"]: ", ucred->pid);
                iovec[n++] = IOVEC_MAKE_STRING(header_pid);
        } else if (identifier) {
                iovec[n++] = IOVEC_MAKE_STRING(identifier);
                iovec[n++] = IOVEC_MAKE_STRING(": ");
        }

        /* Fourth: message */
        iovec[n++] = IOVEC_MAKE_STRING(message);
        iovec[n++] = IOVEC_MAKE_STRING("\n");

        if (writev(s->dev_kmsg_fd, iovec, n) < 0)
                log_debug_errno(errno, "Failed to write to /dev/kmsg for logging, ignoring: %m");
}

static bool is_us(const char *identifier, const char *pid) {
        pid_t pid_num;

        if (!identifier || !pid)
                return false;

        if (parse_pid(pid, &pid_num) < 0)
                return false;

        return pid_num == getpid_cached() &&
               streq(identifier, program_invocation_short_name);
}

void dev_kmsg_record(Server *s, char *p, size_t l) {

        _cleanup_free_ char *message = NULL, *syslog_pid = NULL, *syslog_identifier = NULL, *identifier = NULL, *pid = NULL;
        struct iovec iovec[N_IOVEC_META_FIELDS + 7 + N_IOVEC_KERNEL_FIELDS + 2 + N_IOVEC_UDEV_FIELDS];
        char *kernel_device = NULL;
        unsigned long long usec;
        size_t n = 0, z = 0, j;
        int priority, r;
        char *e, *f, *k;
        uint64_t serial;
        size_t pl;
        int saved_log_max_level = INT_MAX;
        ClientContext *c = NULL;

        assert(s);
        assert(p);

        if (l <= 0)
                return;

        e = memchr(p, ',', l);
        if (!e)
                return;
        *e = 0;

        r = safe_atoi(p, &priority);
        if (r < 0 || priority < 0 || priority > 999)
                return;

        if (s->forward_to_kmsg && LOG_FAC(priority) != LOG_KERN)
                return;

        l -= (e - p) + 1;
        p = e + 1;
        e = memchr(p, ',', l);
        if (!e)
                return;
        *e = 0;

        r = safe_atou64(p, &serial);
        if (r < 0)
                return;

        if (s->kernel_seqnum) {
                /* We already read this one? */
                if (serial < *s->kernel_seqnum)
                        return;

                /* Did we lose any? */
                if (serial > *s->kernel_seqnum)
                        server_driver_message(s, 0,
                                              "MESSAGE_ID=" SD_MESSAGE_JOURNAL_MISSED_STR,
                                              LOG_MESSAGE("Missed %"PRIu64" kernel messages",
                                                          serial - *s->kernel_seqnum),
                                              NULL);

                /* Make sure we never read this one again. Note that
                 * we always store the next message serial we expect
                 * here, simply because this makes handling the first
                 * message with serial 0 easy. */
                *s->kernel_seqnum = serial + 1;
        }

        l -= (e - p) + 1;
        p = e + 1;
        f = memchr(p, ';', l);
        if (!f)
                return;
        /* Kernel 3.6 has the flags field, kernel 3.5 lacks that */
        e = memchr(p, ',', l);
        if (!e || f < e)
                e = f;
        *e = 0;

        r = safe_atollu(p, &usec);
        if (r < 0)
                return;

        l -= (f - p) + 1;
        p = f + 1;
        e = memchr(p, '\n', l);
        if (!e)
                return;
        *e = 0;

        pl = e - p;
        l -= (e - p) + 1;
        k = e + 1;

        for (j = 0; l > 0 && j < N_IOVEC_KERNEL_FIELDS; j++) {
                char *m;
                /* Metadata fields attached */

                if (*k != ' ')
                        break;

                k++, l--;

                e = memchr(k, '\n', l);
                if (!e)
                        goto finish;

                *e = 0;

                if (cunescape_length_with_prefix(k, e - k, "_KERNEL_", UNESCAPE_RELAX, &m) < 0)
                        break;

                if (startswith(m, "_KERNEL_DEVICE="))
                        kernel_device = m + 15;

                iovec[n++] = IOVEC_MAKE_STRING(m);
                z++;

                l -= (e - k) + 1;
                k = e + 1;
        }

        if (kernel_device) {
                _cleanup_(sd_device_unrefp) sd_device *d = NULL;

                if (sd_device_new_from_device_id(&d, kernel_device) >= 0) {
                        const char *g;
                        char *b;

                        if (sd_device_get_devname(d, &g) >= 0) {
                                b = strjoin("_UDEV_DEVNODE=", g);
                                if (b) {
                                        iovec[n++] = IOVEC_MAKE_STRING(b);
                                        z++;
                                }
                        }

                        if (sd_device_get_sysname(d, &g) >= 0) {
                                b = strjoin("_UDEV_SYSNAME=", g);
                                if (b) {
                                        iovec[n++] = IOVEC_MAKE_STRING(b);
                                        z++;
                                }
                        }

                        j = 0;
                        FOREACH_DEVICE_DEVLINK(d, link) {

                                if (j >= N_IOVEC_UDEV_FIELDS)
                                        break;

                                b = strjoin("_UDEV_DEVLINK=", link);
                                if (b) {
                                        iovec[n++] = IOVEC_MAKE_STRING(b);
                                        z++;
                                }

                                j++;
                        }
                }
        }

        char source_boot_time[STRLEN("_SOURCE_BOOTTIME_TIMESTAMP=") + DECIMAL_STR_MAX(unsigned long long)];
        xsprintf(source_boot_time, "_SOURCE_BOOTTIME_TIMESTAMP=%llu", usec);
        iovec[n++] = IOVEC_MAKE_STRING(source_boot_time);

        /* Historically, we stored the timestamp 'usec' as _SOURCE_MONOTONIC_TIMESTAMP, so we cannot remove
         * the field as it is already used in other projects. This is for backward compatibility. */
        char source_monotonic_time[STRLEN("_SOURCE_MONOTONIC_TIMESTAMP=") + DECIMAL_STR_MAX(unsigned long long)];
        xsprintf(source_monotonic_time, "_SOURCE_MONOTONIC_TIMESTAMP=%llu", usec);
        iovec[n++] = IOVEC_MAKE_STRING(source_monotonic_time);

        iovec[n++] = IOVEC_MAKE_STRING("_TRANSPORT=kernel");

        char syslog_priority[STRLEN("PRIORITY=") + DECIMAL_STR_MAX(int)];
        xsprintf(syslog_priority, "PRIORITY=%i", LOG_PRI(priority));
        iovec[n++] = IOVEC_MAKE_STRING(syslog_priority);

        char syslog_facility[STRLEN("SYSLOG_FACILITY=") + DECIMAL_STR_MAX(int)];
        xsprintf(syslog_facility, "SYSLOG_FACILITY=%i", LOG_FAC(priority));
        iovec[n++] = IOVEC_MAKE_STRING(syslog_facility);

        if (LOG_FAC(priority) == LOG_KERN)
                iovec[n++] = IOVEC_MAKE_STRING("SYSLOG_IDENTIFIER=kernel");
        else {
                pl -= syslog_parse_identifier((const char**) &p, &identifier, &pid);

                /* Avoid logging any new messages when we're processing messages generated by ourselves via
                 * log_info() and friends to avoid infinite loops. */
                if (is_us(identifier, pid)) {
                        if (!ratelimit_below(&s->kmsg_own_ratelimit))
                                return;

                        saved_log_max_level = log_get_max_level();
                        c = s->my_context;
                        log_set_max_level(LOG_NULL);
                }

                if (identifier) {
                        syslog_identifier = strjoin("SYSLOG_IDENTIFIER=", identifier);
                        if (syslog_identifier)
                                iovec[n++] = IOVEC_MAKE_STRING(syslog_identifier);
                }

                if (pid) {
                        syslog_pid = strjoin("SYSLOG_PID=", pid);
                        if (syslog_pid)
                                iovec[n++] = IOVEC_MAKE_STRING(syslog_pid);
                }
        }

        if (cunescape_length_with_prefix(p, pl, "MESSAGE=", UNESCAPE_RELAX, &message) >= 0)
                iovec[n++] = IOVEC_MAKE_STRING(message);

        server_dispatch_message(s, iovec, n, ELEMENTSOF(iovec), c, NULL, priority, 0);

        if (saved_log_max_level != INT_MAX)
                log_set_max_level(saved_log_max_level);

finish:
        for (j = 0; j < z; j++)
                free(iovec[j].iov_base);
}

static int server_read_dev_kmsg(Server *s) {
        char buffer[8192+1]; /* the kernel-side limit per record is 8K currently */
        ssize_t l;

        assert(s);
        assert(s->dev_kmsg_fd >= 0);

        l = read(s->dev_kmsg_fd, buffer, sizeof(buffer) - 1);
        if (l == 0)
                return 0;
        if (l < 0) {
                /* Old kernels which don't allow reading from /dev/kmsg return EINVAL when we try. So handle
                 * this cleanly, but don't try to ever read from it again. */
                if (errno == EINVAL) {
                        s->dev_kmsg_event_source = sd_event_source_unref(s->dev_kmsg_event_source);
                        s->dev_kmsg_readable = false;
                        return 0;
                }

                if (ERRNO_IS_TRANSIENT(errno) || errno == EPIPE)
                        return 0;

                return log_ratelimit_error_errno(errno, JOURNAL_LOG_RATELIMIT, "Failed to read from /dev/kmsg: %m");
        }

        dev_kmsg_record(s, buffer, l);
        return 1;
}

int server_flush_dev_kmsg(Server *s) {
        int r;

        assert(s);

        if (s->dev_kmsg_fd < 0)
                return 0;

        if (!s->dev_kmsg_readable)
                return 0;

        log_debug("Flushing /dev/kmsg...");

        for (;;) {
                r = server_read_dev_kmsg(s);
                if (r < 0)
                        return r;

                if (r == 0)
                        break;
        }

        return 0;
}

static int dispatch_dev_kmsg(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        Server *s = ASSERT_PTR(userdata);

        assert(es);
        assert(fd == s->dev_kmsg_fd);

        if (revents & EPOLLERR)
                log_ratelimit_warning(JOURNAL_LOG_RATELIMIT,
                                      "/dev/kmsg buffer overrun, some messages lost.");

        if (!(revents & EPOLLIN))
                log_error("Got invalid event from epoll for /dev/kmsg: %"PRIx32, revents);

        return server_read_dev_kmsg(s);
}

int server_open_dev_kmsg(Server *s) {
        int r;

        assert(s);

        mode_t mode = O_CLOEXEC|O_NONBLOCK|O_NOCTTY|
                (s->read_kmsg ? O_RDWR : O_WRONLY);

        s->dev_kmsg_fd = open("/dev/kmsg", mode);
        if (s->dev_kmsg_fd < 0) {
                log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING,
                               errno, "Failed to open /dev/kmsg for %s access, ignoring: %m", accmode_to_string(mode));
                return 0;
        }

        if (!s->read_kmsg)
                return 0;

        r = sd_event_add_io(s->event, &s->dev_kmsg_event_source, s->dev_kmsg_fd, EPOLLIN, dispatch_dev_kmsg, s);
        if (r == -EPERM) { /* This will fail with EPERM on older kernels where /dev/kmsg is not readable. */
                log_debug_errno(r, "Not reading from /dev/kmsg since that's not supported, apparently.");
                r = 0;
                goto finish;
        }
        if (r < 0) {
                log_error_errno(r, "Failed to add /dev/kmsg fd to event loop: %m");
                goto finish;
        }

        r = sd_event_source_set_priority(s->dev_kmsg_event_source, SD_EVENT_PRIORITY_IMPORTANT+10);
        if (r < 0) {
                log_error_errno(r, "Failed to adjust priority of kmsg event source: %m");
                goto finish;
        }

        s->dev_kmsg_readable = true;
        return 0;

finish:
        s->dev_kmsg_event_source = sd_event_source_unref(s->dev_kmsg_event_source);
        s->dev_kmsg_fd = safe_close(s->dev_kmsg_fd);
        return r;
}

int server_open_kernel_seqnum(Server *s) {
        int r;

        assert(s);

        /* We store the seqnum we last read in an mmapped file. That way we can just use it like a variable,
         * but it is persistent and automatically flushed at reboot. */

        if (!s->dev_kmsg_readable)
                return 0;

        r = server_map_seqnum_file(s, "kernel-seqnum", sizeof(uint64_t), (void**) &s->kernel_seqnum);
        if (r < 0)
                return log_error_errno(r, "Failed to map kernel seqnum file: %m");

        return 0;
}
