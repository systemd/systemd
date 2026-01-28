/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-event.h"
#include "sd-messages.h"

#include "alloc-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "format-util.h"
#include "iovec-util.h"
#include "journal-internal.h"
#include "journald-kmsg.h"
#include "journald-manager.h"
#include "journald-sync.h"
#include "journald-syslog.h"
#include "log.h"
#include "log-ratelimit.h"
#include "parse-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "string-util.h"

void manager_forward_kmsg(
                Manager *m,
                int priority,
                const char *identifier,
                const char *message,
                const struct ucred *ucred) {

        _cleanup_free_ char *ident_buf = NULL;
        struct iovec iovec[5];
        char header_priority[DECIMAL_STR_MAX(priority) + 3],
             header_pid[STRLEN("[]: ") + DECIMAL_STR_MAX(pid_t) + 1];
        size_t n = 0;

        assert(m);
        assert(priority >= 0);
        assert(priority <= 999);
        assert(message);

        if (_unlikely_(LOG_PRI(priority) > m->config.max_level_kmsg))
                return;

        if (_unlikely_(m->dev_kmsg_fd < 0))
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

        if (writev(m->dev_kmsg_fd, iovec, n) < 0)
                log_debug_errno(errno, "Failed to write to /dev/kmsg for logging, ignoring: %m");
}

static bool is_us(const char *identifier, pid_t pid) {
        if (!identifier || !pid_is_valid(pid))
                return false;

        return pid == getpid_cached() &&
               streq(identifier, program_invocation_short_name);
}

void dev_kmsg_record(Manager *m, char *p, size_t l) {

        _cleanup_free_ char *message = NULL, *syslog_identifier = NULL;
        struct iovec iovec[N_IOVEC_META_FIELDS + 7 + N_IOVEC_KERNEL_FIELDS + 2 + N_IOVEC_UDEV_FIELDS];
        char *kernel_device = NULL;
        unsigned long long usec;
        size_t n = 0, z = 0, j;
        int priority, r;
        char *e, *k, syslog_pid[STRLEN("SYSLOG_PID=") + DECIMAL_STR_MAX(pid_t)];
        uint64_t serial;
        size_t pl;
        int saved_log_max_level = INT_MAX;
        ClientContext *c = NULL;

        assert(m);
        assert(p);

        if (l <= 0)
                return;

        /* syslog prefix including priority and facility */
        e = memchr(p, ',', l);
        if (!e)
                return;
        *e = 0;

        r = safe_atoi(p, &priority);
        if (r < 0 || priority < 0 || priority > 999)
                return;

        if (m->config.forward_to_kmsg && LOG_FAC(priority) != LOG_KERN)
                return;

        /* seqnum */
        l -= (e - p) + 1;
        p = e + 1;
        e = memchr(p, ',', l);
        if (!e)
                return;
        *e = 0;

        r = safe_atou64(p, &serial);
        if (r < 0)
                return;

        if (m->kernel_seqnum) {
                /* We already read this one? */
                if (serial < *m->kernel_seqnum)
                        return;

                /* Did we lose any? */
                if (serial > *m->kernel_seqnum)
                        manager_driver_message(m, 0,
                                               LOG_MESSAGE_ID(SD_MESSAGE_JOURNAL_MISSED_STR),
                                               LOG_MESSAGE("Missed %"PRIu64" kernel messages",
                                                           serial - *m->kernel_seqnum));

                /* Make sure we never read this one again. Note that
                 * we always store the next message serial we expect
                 * here, simply because this makes handling the first
                 * message with serial 0 easy. */
                *m->kernel_seqnum = serial + 1;
        }

        /* CLOCK_BOOTTIME timestamp */
        l -= (e - p) + 1;
        p = e + 1;
        e = memchr(p, ',', l);
        if (!e)
                return;
        *e = 0;

        r = safe_atollu(p, &usec);
        if (r < 0)
                return;

        /* ignore flags and any other fields, and find the beginning of the message */
        l -= (e - p) + 1;
        p = e + 1;
        e = memchr(p, ';', l);
        if (!e)
                return;

        /* find the end of the message */
        l -= (e - p) + 1;
        p = e + 1;
        e = memchr(p, '\n', l);
        if (!e)
                return;
        *e = 0;

        pl = e - p;
        l -= (e - p) + 1;
        k = e + 1;

        for (j = 0; l > 0 && j < N_IOVEC_KERNEL_FIELDS; j++) {
                char *mm;
                /* Metadata fields attached */

                if (*k != ' ')
                        break;

                k++, l--;

                e = memchr(k, '\n', l);
                if (!e)
                        goto finish;

                *e = 0;

                if (cunescape_length_with_prefix(k, e - k, "_KERNEL_", UNESCAPE_RELAX, &mm) < 0)
                        break;

                if (startswith(mm, "_KERNEL_DEVICE="))
                        kernel_device = mm + 15;

                iovec[n++] = IOVEC_MAKE_STRING(mm);
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
                _cleanup_free_ char *identifier = NULL;
                pid_t pid;

                pl -= syslog_parse_identifier((const char**) &p, &identifier, &pid);

                /* Avoid logging any new messages when we're processing messages generated by ourselves via
                 * log_info() and friends to avoid infinite loops. */
                if (is_us(identifier, pid)) {
                        if (!ratelimit_below(&m->kmsg_own_ratelimit))
                                return;

                        saved_log_max_level = log_get_max_level();
                        c = m->my_context;
                        log_set_max_level(LOG_NULL);
                }

                if (identifier) {
                        syslog_identifier = strjoin("SYSLOG_IDENTIFIER=", identifier);
                        if (syslog_identifier)
                                iovec[n++] = IOVEC_MAKE_STRING(syslog_identifier);
                }

                if (pid_is_valid(pid)) {
                        xsprintf(syslog_pid, "SYSLOG_PID="PID_FMT, pid);
                        iovec[n++] = IOVEC_MAKE_STRING(syslog_pid);
                }
        }

        if (cunescape_length_with_prefix(p, pl, "MESSAGE=", UNESCAPE_RELAX, &message) >= 0)
                iovec[n++] = IOVEC_MAKE_STRING(message);

        manager_dispatch_message(m, iovec, n, ELEMENTSOF(iovec), c, NULL, priority, 0);

        if (saved_log_max_level != INT_MAX)
                log_set_max_level(saved_log_max_level);

        m->dev_kmsg_timestamp = usec;
        sync_req_revalidate_by_timestamp(m);

finish:
        for (j = 0; j < z; j++)
                free(iovec[j].iov_base);
}

static int manager_read_dev_kmsg(Manager *m) {
        char buffer[8192+1]; /* the kernel-side limit per record is 8K currently */
        ssize_t l;

        assert(m);
        assert(m->dev_kmsg_fd >= 0);
        assert(m->config.read_kmsg);

        l = read(m->dev_kmsg_fd, buffer, sizeof(buffer) - 1);
        if (l == 0)
                return 0;
        if (l < 0) {
                if (ERRNO_IS_TRANSIENT(errno) || errno == EPIPE)
                        return 0;

                return log_ratelimit_error_errno(errno, JOURNAL_LOG_RATELIMIT, "Failed to read from /dev/kmsg: %m");
        }

        dev_kmsg_record(m, buffer, l);
        return 1;
}

int manager_flush_dev_kmsg(Manager *m) {
        int r;

        assert(m);

        if (m->dev_kmsg_fd < 0)
                return 0;

        if (!m->config.read_kmsg)
                return 0;

        log_debug("Flushing /dev/kmsg...");

        for (;;) {
                r = manager_read_dev_kmsg(m);
                if (r <= 0)
                        return r;
        }

        return 0;
}

static int dispatch_dev_kmsg(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(es);
        assert(fd == m->dev_kmsg_fd);

        if (revents & EPOLLERR)
                log_ratelimit_warning(JOURNAL_LOG_RATELIMIT,
                                      "/dev/kmsg buffer overrun, some messages lost.");

        if (!(revents & EPOLLIN))
                log_error("Got invalid event from epoll for /dev/kmsg: %"PRIx32, revents);

        return manager_read_dev_kmsg(m);
}

int manager_open_dev_kmsg(Manager *m) {
        int r;

        assert(m);
        assert(m->dev_kmsg_fd < 0);
        assert(!m->dev_kmsg_event_source);

        mode_t mode = O_CLOEXEC|O_NONBLOCK|O_NOCTTY|(m->config.read_kmsg ? O_RDWR : O_WRONLY);

        _cleanup_close_ int fd = open("/dev/kmsg", mode);
        if (fd < 0) {
                log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING,
                               errno, "Failed to open /dev/kmsg for %s access, ignoring: %m", accmode_to_string(mode));
                return 0;
        }

        if (!m->config.read_kmsg) {
                m->dev_kmsg_fd = TAKE_FD(fd);
                return 0;
        }

        _cleanup_(sd_event_source_unrefp) sd_event_source *es = NULL;
        r = sd_event_add_io(m->event, &es, fd, EPOLLIN, dispatch_dev_kmsg, m);
        if (r < 0)
                return log_error_errno(r, "Failed to add /dev/kmsg fd to event loop: %m");

        r = sd_event_source_set_priority(es, SD_EVENT_PRIORITY_NORMAL+5);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust priority of kmsg event source: %m");

        m->dev_kmsg_fd = TAKE_FD(fd);
        m->dev_kmsg_event_source = TAKE_PTR(es);
        return 0;
}

int manager_open_kernel_seqnum(Manager *m) {
        int r;

        assert(m);
        assert(!m->kernel_seqnum);

        /* We store the seqnum we last read in an mmapped file. That way we can just use it like a variable,
         * but it is persistent and automatically flushed at reboot. */

        if (!m->config.read_kmsg)
                return 0;

        r = manager_map_seqnum_file(m, "kernel-seqnum", sizeof(uint64_t), (void**) &m->kernel_seqnum);
        if (r < 0)
                return log_error_errno(r, "Failed to map kernel seqnum file: %m");

        return 0;
}

void manager_close_kernel_seqnum(Manager *m) {
        assert(m);

        manager_unmap_seqnum_file(m->kernel_seqnum, sizeof(*m->kernel_seqnum));
        m->kernel_seqnum = NULL;
}

static int manager_unlink_kernel_seqnum(Manager *m) {
        assert(m);
        assert(!m->kernel_seqnum); /* The file must not be mmap()ed. */

        return manager_unlink_seqnum_file(m, "kernel-seqnum");
}

int manager_reopen_dev_kmsg(Manager *m, bool old_read_kmsg) {
        int r;

        assert(m);

        /* If the fd has not yet been initialized, let's shortcut and simply open /dev/kmsg. */
        if (m->dev_kmsg_fd < 0)
                return manager_open_dev_kmsg(m);

        if (m->config.read_kmsg == old_read_kmsg)
                return 0; /* Setting is unchanged. */

        if (!m->config.read_kmsg) {
                /* If reading kmsg was enabled but now disable, let's flush the buffer before disabling it. */
                m->config.read_kmsg = true;
                (void) manager_flush_dev_kmsg(m);
                m->config.read_kmsg = false;

                /* seqnum file is not necessary anymore. Let's close it. */
                manager_close_kernel_seqnum(m);

                /* Also, unlink the file name as we will not warn some kmsg are lost when reading kmsg is
                 * re-enabled later. */
                manager_unlink_kernel_seqnum(m);
        }

        /* Close previously configured event source and opened file descriptor. */
        m->dev_kmsg_event_source = sd_event_source_disable_unref(m->dev_kmsg_event_source);
        m->dev_kmsg_fd = safe_close(m->dev_kmsg_fd);

        r = manager_open_dev_kmsg(m);
        if (r < 0)
                return r;

        return manager_open_kernel_seqnum(m);
}
