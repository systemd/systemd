/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stddef.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "iovec-util.h"
#include "journal-importer.h"
#include "journal-internal.h"
#include "journal-util.h"
#include "journald-client.h"
#include "journald-console.h"
#include "journald-kmsg.h"
#include "journald-native.h"
#include "journald-server.h"
#include "journald-syslog.h"
#include "journald-wall.h"
#include "memfd-util.h"
#include "memory-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "selinux-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "unaligned.h"

static bool allow_object_pid(const struct ucred *ucred) {
        return ucred && ucred->uid == 0;
}

static void server_process_entry_meta(
                const char *p, size_t l,
                const struct ucred *ucred,
                int *priority,
                char **identifier,
                char **message,
                pid_t *object_pid) {

        /* We need to determine the priority of this entry for the rate limiting logic */

        if (l == 10 &&
            startswith(p, "PRIORITY=") &&
            p[9] >= '0' && p[9] <= '9')
                *priority = (*priority & LOG_FACMASK) | (p[9] - '0');

        else if (l == 17 &&
                 startswith(p, "SYSLOG_FACILITY=") &&
                 p[16] >= '0' && p[16] <= '9')
                *priority = LOG_PRI(*priority) | ((p[16] - '0') << 3);

        else if (l == 18 &&
                 startswith(p, "SYSLOG_FACILITY=") &&
                 p[16] >= '0' && p[16] <= '9' &&
                 p[17] >= '0' && p[17] <= '9')
                *priority = LOG_PRI(*priority) | (((p[16] - '0')*10 + (p[17] - '0')) << 3);

        else if (l >= 19 &&
                 startswith(p, "SYSLOG_IDENTIFIER=")) {
                char *t;

                t = memdup_suffix0(p + 18, l - 18);
                if (t)
                        free_and_replace(*identifier, t);

        } else if (l >= 8 &&
                   startswith(p, "MESSAGE=")) {
                char *t;

                t = memdup_suffix0(p + 8, l - 8);
                if (t)
                        free_and_replace(*message, t);

        } else if (l > STRLEN("OBJECT_PID=") &&
                   l < STRLEN("OBJECT_PID=")  + DECIMAL_STR_MAX(pid_t) &&
                   startswith(p, "OBJECT_PID=") &&
                   allow_object_pid(ucred)) {
                char buf[DECIMAL_STR_MAX(pid_t)];
                memcpy(buf, p + STRLEN("OBJECT_PID="),
                       l - STRLEN("OBJECT_PID="));
                buf[l-STRLEN("OBJECT_PID=")] = '\0';

                (void) parse_pid(buf, object_pid);
        }
}

static int server_process_entry(
                Server *s,
                const void *buffer, size_t *remaining,
                ClientContext *context,
                const struct ucred *ucred,
                const struct timeval *tv,
                const char *label, size_t label_len) {

        /* Process a single entry from a native message. Returns 0 if nothing special happened and the message
         * processing should continue, and a negative or positive value otherwise.
         *
         * Note that *remaining is altered on both success and failure. */

        size_t n = 0, j, tn = SIZE_MAX, entry_size = 0;
        char *identifier = NULL, *message = NULL;
        struct iovec *iovec = NULL;
        int priority = LOG_INFO;
        pid_t object_pid = 0;
        const char *p;
        int r = 1;

        p = buffer;

        while (*remaining > 0) {
                const char *e, *q;

                e = memchr(p, '\n', *remaining);

                if (!e) {
                        /* Trailing noise, let's ignore it, and flush what we collected */
                        log_debug("Received message with trailing noise, ignoring.");
                        break; /* finish processing of the message */
                }

                if (e == p) {
                        /* Entry separator */
                        *remaining -= 1;
                        break;
                }

                if (IN_SET(*p, '.', '#')) {
                        /* Ignore control commands for now, and comments too. */
                        *remaining -= (e - p) + 1;
                        p = e + 1;
                        continue;
                }

                /* A property follows */
                if (n > ENTRY_FIELD_COUNT_MAX) {
                        log_debug("Received an entry that has more than " STRINGIFY(ENTRY_FIELD_COUNT_MAX) " fields, ignoring entry.");
                        goto finish;
                }

                /* n existing properties, 1 new, +1 for _TRANSPORT */
                if (!GREEDY_REALLOC(iovec,
                                    n + 2 +
                                    N_IOVEC_META_FIELDS + N_IOVEC_OBJECT_FIELDS +
                                    client_context_extra_fields_n_iovec(context))) {
                        r = log_oom();
                        goto finish;
                }

                q = memchr(p, '=', e - p);
                if (q) {
                        if (journal_field_valid(p, q - p, false)) {
                                size_t l;

                                l = e - p;
                                if (l > DATA_SIZE_MAX) {
                                        log_debug("Received text block of %zu bytes is too large, ignoring entry.", l);
                                        goto finish;
                                }

                                if (entry_size + l + n + 1 > ENTRY_SIZE_MAX) { /* data + separators + trailer */
                                        log_debug("Entry is too big (%zu bytes after processing %zu entries), ignoring entry.",
                                                  entry_size + l, n + 1);
                                        goto finish;
                                }

                                /* If the field name starts with an underscore, skip the variable, since that indicates
                                 * a trusted field */
                                iovec[n++] = IOVEC_MAKE((char*) p, l);
                                entry_size += l;

                                server_process_entry_meta(p, l, ucred,
                                                          &priority,
                                                          &identifier,
                                                          &message,
                                                          &object_pid);
                        }

                        *remaining -= (e - p) + 1;
                        p = e + 1;
                        continue;
                } else {
                        uint64_t l, total;
                        char *k;

                        if (*remaining < e - p + 1 + sizeof(uint64_t) + 1) {
                                log_debug("Failed to parse message, ignoring.");
                                break;
                        }

                        l = unaligned_read_le64(e + 1);
                        if (l > DATA_SIZE_MAX) {
                                log_debug("Received binary data block of %"PRIu64" bytes is too large, ignoring entry.", l);
                                goto finish;
                        }

                        total = (e - p) + 1 + l;
                        if (entry_size + total + n + 1 > ENTRY_SIZE_MAX) { /* data + separators + trailer */
                                log_debug("Entry is too big (%"PRIu64"bytes after processing %zu fields), ignoring.",
                                          entry_size + total, n + 1);
                                goto finish;
                        }

                        if ((uint64_t) *remaining < e - p + 1 + sizeof(uint64_t) + l + 1 ||
                            e[1+sizeof(uint64_t)+l] != '\n') {
                                log_debug("Failed to parse message, ignoring.");
                                break;
                        }

                        k = malloc(total);
                        if (!k) {
                                log_oom();
                                break;
                        }

                        memcpy(k, p, e - p);
                        k[e - p] = '=';
                        memcpy(k + (e - p) + 1, e + 1 + sizeof(uint64_t), l);

                        if (journal_field_valid(p, e - p, false)) {
                                iovec[n] = IOVEC_MAKE(k, (e - p) + 1 + l);
                                entry_size += iovec[n].iov_len;
                                n++;

                                server_process_entry_meta(k, (e - p) + 1 + l, ucred,
                                                          &priority,
                                                          &identifier,
                                                          &message,
                                                          &object_pid);
                        } else
                                free(k);

                        *remaining -= (e - p) + 1 + sizeof(uint64_t) + l + 1;
                        p = e + 1 + sizeof(uint64_t) + l + 1;
                }
        }

        if (n <= 0)
                goto finish;

        tn = n++;
        iovec[tn] = IOVEC_MAKE_STRING("_TRANSPORT=journal");
        entry_size += STRLEN("_TRANSPORT=journal");

        if (entry_size + n + 1 > ENTRY_SIZE_MAX) { /* data + separators + trailer */
                log_debug("Entry is too big with %zu properties and %zu bytes, ignoring.", n, entry_size);
                goto finish;
        }

        r = 0; /* Success, we read the message. */

        if (!client_context_test_priority(context, priority))
                goto finish;

        if (message) {
                /* Ensure message is not NULL, otherwise strlen(message) would crash. This check needs to
                 * be here until server_process_entry() is able to process messages containing \0 characters,
                 * as we would have access to the actual size of message. */
                r = client_context_check_keep_log(context, message, strlen(message));
                if (r <= 0)
                        goto finish;

                if (s->forward_to_syslog)
                        server_forward_syslog(s, syslog_fixup_facility(priority), identifier, message, ucred, tv);

                if (s->forward_to_kmsg)
                        server_forward_kmsg(s, priority, identifier, message, ucred);

                if (s->forward_to_console)
                        server_forward_console(s, priority, identifier, message, ucred);

                if (s->forward_to_wall)
                        server_forward_wall(s, priority, identifier, message, ucred);
        }

        server_dispatch_message(s, iovec, n, MALLOC_ELEMENTSOF(iovec), context, tv, priority, object_pid);

finish:
        for (j = 0; j < n; j++)  {
                if (j == tn)
                        continue;

                if (iovec[j].iov_base < buffer ||
                    (const char*) iovec[j].iov_base >= p + *remaining)
                        free(iovec[j].iov_base);
        }

        free(iovec);
        free(identifier);
        free(message);

        return r;
}

void server_process_native_message(
                Server *s,
                const char *buffer, size_t buffer_size,
                const struct ucred *ucred,
                const struct timeval *tv,
                const char *label, size_t label_len) {

        size_t remaining = buffer_size;
        ClientContext *context = NULL;
        int r;

        assert(s);
        assert(buffer || buffer_size == 0);

        if (ucred && pid_is_valid(ucred->pid)) {
                r = client_context_get(s, ucred->pid, ucred, label, label_len, NULL, &context);
                if (r < 0)
                        log_ratelimit_warning_errno(r, JOURNAL_LOG_RATELIMIT,
                                                    "Failed to retrieve credentials for PID " PID_FMT ", ignoring: %m",
                                                    ucred->pid);
        }

        do {
                r = server_process_entry(s,
                                         (const uint8_t*) buffer + (buffer_size - remaining), &remaining,
                                         context, ucred, tv, label, label_len);
        } while (r == 0);
}

int server_process_native_file(
                Server *s,
                int fd,
                const struct ucred *ucred,
                const struct timeval *tv,
                const char *label, size_t label_len) {

        struct stat st;
        bool sealed;
        int r;

        /* Data is in the passed fd, probably it didn't fit in a datagram. */

        assert(s);
        assert(fd >= 0);

        if (fstat(fd, &st) < 0)
                return log_ratelimit_error_errno(errno, JOURNAL_LOG_RATELIMIT,
                                                 "Failed to stat passed file: %m");

        r = stat_verify_regular(&st);
        if (r < 0)
                return log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT,
                                                 "File passed is not regular, ignoring message: %m");

        if (st.st_size <= 0)
                return 0;

        r = fd_verify_safe_flags(fd);
        if (r == -EREMOTEIO)
                return log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT,
                                                 "Unexpected flags of passed memory fd, ignoring message.");
        if (r < 0)
                return log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT,
                                                 "Failed to get flags of passed file: %m");

        /* If it's a memfd, check if it is sealed. If so, we can just mmap it and use it, and do not need to
         * copy the data out. */
        sealed = memfd_get_sealed(fd) > 0;

        if (!sealed && (!ucred || ucred->uid != 0)) {
                _cleanup_free_ char *k = NULL;
                const char *e;

                /* If this is not a sealed memfd, and the peer is unknown or unprivileged, then verify the
                 * path. */

                r = fd_get_path(fd, &k);
                if (r < 0)
                        return log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT,
                                                         "Failed to get path of passed fd: %m");

                e = PATH_STARTSWITH_SET(k, "/dev/shm/", "/tmp/", "/var/tmp/");
                if (!e)
                        return log_ratelimit_error_errno(SYNTHETIC_ERRNO(EPERM), JOURNAL_LOG_RATELIMIT,
                                                         "Received file outside of allowed directories, refusing.");

                if (!filename_is_valid(e))
                        return log_ratelimit_error_errno(SYNTHETIC_ERRNO(EPERM), JOURNAL_LOG_RATELIMIT,
                                                         "Received file in subdirectory of allowed directories, refusing.");
        }

        /* When !sealed, set a lower memory limit. We have to read the file, effectively doubling memory
         * use. */
        if (st.st_size > ENTRY_SIZE_MAX / (sealed ? 1 : 2))
                return log_ratelimit_error_errno(SYNTHETIC_ERRNO(EFBIG), JOURNAL_LOG_RATELIMIT,
                                                 "File passed too large (%"PRIu64" bytes), refusing.",
                                                 (uint64_t) st.st_size);

        if (sealed) {
                void *p;
                size_t ps;

                /* The file is sealed, we can just map it and use it. */

                ps = PAGE_ALIGN(st.st_size);
                assert(ps < SIZE_MAX);
                p = mmap(NULL, ps, PROT_READ, MAP_PRIVATE, fd, 0);
                if (p == MAP_FAILED)
                        return log_ratelimit_error_errno(errno, JOURNAL_LOG_RATELIMIT,
                                                         "Failed to map memfd: %m");

                server_process_native_message(s, p, st.st_size, ucred, tv, label, label_len);
                assert_se(munmap(p, ps) >= 0);

                return 0;
        }

        _cleanup_free_ void *p = NULL;
        struct statvfs vfs;
        ssize_t n;

        if (fstatvfs(fd, &vfs) < 0)
                return log_ratelimit_error_errno(errno, JOURNAL_LOG_RATELIMIT,
                                                 "Failed to stat file system of passed file: %m");

        /* Refuse operating on file systems that have mandatory locking enabled.
         * See also: https://github.com/systemd/systemd/issues/1822 */
        if (FLAGS_SET(vfs.f_flag, ST_MANDLOCK))
                return log_ratelimit_error_errno(SYNTHETIC_ERRNO(EPERM), JOURNAL_LOG_RATELIMIT,
                                                 "Received file descriptor from file system with mandatory locking enabled, not processing it.");

        /* Make the fd non-blocking. On regular files this has the effect of bypassing mandatory
         * locking. Of course, this should normally not be necessary given the check above, but let's
         * better be safe than sorry, after all NFS is pretty confusing regarding file system flags,
         * and we better don't trust it, and so is SMB. */
        r = fd_nonblock(fd, true);
        if (r < 0)
                return log_ratelimit_error_errno(r, JOURNAL_LOG_RATELIMIT,
                                                 "Failed to make fd non-blocking: %m");

        /* The file is not sealed, we can't map the file here, since clients might then truncate it
         * and trigger a SIGBUS for us. So let's stupidly read it. */

        p = malloc(st.st_size);
        if (!p)
                return log_oom();

        n = pread(fd, p, st.st_size, 0);
        if (n < 0)
                return log_ratelimit_error_errno(errno, JOURNAL_LOG_RATELIMIT,
                                                 "Failed to read file: %m");
        if (n > 0)
                server_process_native_message(s, p, n, ucred, tv, label, label_len);

        return 0;
}

int server_open_native_socket(Server *s, const char *native_socket) {
        int r;

        assert(s);
        assert(native_socket);

        if (s->native_fd < 0) {
                union sockaddr_union sa;
                size_t sa_len;

                r = sockaddr_un_set_path(&sa.un, native_socket);
                if (r < 0)
                        return log_error_errno(r, "Unable to use namespace path %s for AF_UNIX socket: %m", native_socket);
                sa_len = r;

                s->native_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (s->native_fd < 0)
                        return log_error_errno(errno, "socket() failed: %m");

                (void) sockaddr_un_unlink(&sa.un);

                r = bind(s->native_fd, &sa.sa, sa_len);
                if (r < 0)
                        return log_error_errno(errno, "bind(%s) failed: %m", sa.un.sun_path);

                (void) chmod(sa.un.sun_path, 0666);
        } else
                (void) fd_nonblock(s->native_fd, true);

        r = setsockopt_int(s->native_fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_error_errno(r, "SO_PASSCRED failed: %m");

        if (mac_selinux_use()) {
                r = setsockopt_int(s->native_fd, SOL_SOCKET, SO_PASSSEC, true);
                if (r < 0)
                        log_warning_errno(r, "SO_PASSSEC failed: %m");
        }

        r = setsockopt_int(s->native_fd, SOL_SOCKET, SO_TIMESTAMP, true);
        if (r < 0)
                return log_error_errno(r, "SO_TIMESTAMP failed: %m");

        r = sd_event_add_io(s->event, &s->native_event_source, s->native_fd, EPOLLIN, server_process_datagram, s);
        if (r < 0)
                return log_error_errno(r, "Failed to add native server fd to event loop: %m");

        r = sd_event_source_set_priority(s->native_event_source, SD_EVENT_PRIORITY_NORMAL+5);
        if (r < 0)
                return log_error_errno(r, "Failed to adjust native event source priority: %m");

        return 0;
}
