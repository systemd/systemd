/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <stddef.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "journald-console.h"
#include "journald-kmsg.h"
#include "journald-native.h"
#include "journald-server.h"
#include "journald-syslog.h"
#include "journald-wall.h"
#include "memfd-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "selinux-util.h"
#include "socket-util.h"
#include "string-util.h"

bool valid_user_field(const char *p, size_t l, bool allow_protected) {
        const char *a;

        /* We kinda enforce POSIX syntax recommendations for
           environment variables here, but make a couple of additional
           requirements.

           http://pubs.opengroup.org/onlinepubs/000095399/basedefs/xbd_chap08.html */

        /* No empty field names */
        if (l <= 0)
                return false;

        /* Don't allow names longer than 64 chars */
        if (l > 64)
                return false;

        /* Variables starting with an underscore are protected */
        if (!allow_protected && p[0] == '_')
                return false;

        /* Don't allow digits as first character */
        if (p[0] >= '0' && p[0] <= '9')
                return false;

        /* Only allow A-Z0-9 and '_' */
        for (a = p; a < p + l; a++)
                if ((*a < 'A' || *a > 'Z') &&
                    (*a < '0' || *a > '9') &&
                    *a != '_')
                        return false;

        return true;
}

static bool allow_object_pid(const struct ucred *ucred) {
        return ucred && ucred->uid == 0;
}

void server_process_native_message(
                Server *s,
                const void *buffer, size_t buffer_size,
                const struct ucred *ucred,
                const struct timeval *tv,
                const char *label, size_t label_len) {

        struct iovec *iovec = NULL;
        unsigned n = 0, j, tn = (unsigned) -1;
        const char *p;
        size_t remaining, m = 0, entry_size = 0;
        int priority = LOG_INFO;
        char *identifier = NULL, *message = NULL;
        pid_t object_pid = 0;

        assert(s);
        assert(buffer || buffer_size == 0);

        p = buffer;
        remaining = buffer_size;

        while (remaining > 0) {
                const char *e, *q;

                e = memchr(p, '\n', remaining);

                if (!e) {
                        /* Trailing noise, let's ignore it, and flush what we collected */
                        log_debug("Received message with trailing noise, ignoring.");
                        break;
                }

                if (e == p) {
                        /* Entry separator */

                        if (entry_size + n + 1 > ENTRY_SIZE_MAX) { /* data + separators + trailer */
                                log_debug("Entry is too big with %u properties and %zu bytes, ignoring.", n, entry_size);
                                continue;
                        }

                        server_dispatch_message(s, iovec, n, m, ucred, tv, label, label_len, NULL, priority, object_pid);
                        n = 0;
                        priority = LOG_INFO;
                        entry_size = 0;

                        p++;
                        remaining--;
                        continue;
                }

                if (*p == '.' || *p == '#') {
                        /* Ignore control commands for now, and
                         * comments too. */
                        remaining -= (e - p) + 1;
                        p = e + 1;
                        continue;
                }

                /* A property follows */

                /* n existing properties, 1 new, +1 for _TRANSPORT */
                if (!GREEDY_REALLOC(iovec, m, n + 2 + N_IOVEC_META_FIELDS + N_IOVEC_OBJECT_FIELDS)) {
                        log_oom();
                        break;
                }

                q = memchr(p, '=', e - p);
                if (q) {
                        if (valid_user_field(p, q - p, false)) {
                                size_t l;

                                l = e - p;

                                /* If the field name starts with an
                                 * underscore, skip the variable,
                                 * since that indidates a trusted
                                 * field */
                                iovec[n].iov_base = (char*) p;
                                iovec[n].iov_len = l;
                                entry_size += iovec[n].iov_len;
                                n++;

                                /* We need to determine the priority
                                 * of this entry for the rate limiting
                                 * logic */
                                if (l == 10 &&
                                    startswith(p, "PRIORITY=") &&
                                    p[9] >= '0' && p[9] <= '9')
                                        priority = (priority & LOG_FACMASK) | (p[9] - '0');

                                else if (l == 17 &&
                                         startswith(p, "SYSLOG_FACILITY=") &&
                                         p[16] >= '0' && p[16] <= '9')
                                        priority = (priority & LOG_PRIMASK) | ((p[16] - '0') << 3);

                                else if (l == 18 &&
                                         startswith(p, "SYSLOG_FACILITY=") &&
                                         p[16] >= '0' && p[16] <= '9' &&
                                         p[17] >= '0' && p[17] <= '9')
                                        priority = (priority & LOG_PRIMASK) | (((p[16] - '0')*10 + (p[17] - '0')) << 3);

                                else if (l >= 19 &&
                                         startswith(p, "SYSLOG_IDENTIFIER=")) {
                                        char *t;

                                        t = strndup(p + 18, l - 18);
                                        if (t) {
                                                free(identifier);
                                                identifier = t;
                                        }

                                } else if (l >= 8 &&
                                           startswith(p, "MESSAGE=")) {
                                        char *t;

                                        t = strndup(p + 8, l - 8);
                                        if (t) {
                                                free(message);
                                                message = t;
                                        }

                                } else if (l > strlen("OBJECT_PID=") &&
                                           l < strlen("OBJECT_PID=")  + DECIMAL_STR_MAX(pid_t) &&
                                           startswith(p, "OBJECT_PID=") &&
                                           allow_object_pid(ucred)) {
                                        char buf[DECIMAL_STR_MAX(pid_t)];
                                        memcpy(buf, p + strlen("OBJECT_PID="), l - strlen("OBJECT_PID="));
                                        char_array_0(buf);

                                        /* ignore error */
                                        parse_pid(buf, &object_pid);
                                }
                        }

                        remaining -= (e - p) + 1;
                        p = e + 1;
                        continue;
                } else {
                        le64_t l_le;
                        uint64_t l;
                        char *k;

                        if (remaining < e - p + 1 + sizeof(uint64_t) + 1) {
                                log_debug("Failed to parse message, ignoring.");
                                break;
                        }

                        memcpy(&l_le, e + 1, sizeof(uint64_t));
                        l = le64toh(l_le);

                        if (l > DATA_SIZE_MAX) {
                                log_debug("Received binary data block of %"PRIu64" bytes is too large, ignoring.", l);
                                break;
                        }

                        if ((uint64_t) remaining < e - p + 1 + sizeof(uint64_t) + l + 1 ||
                            e[1+sizeof(uint64_t)+l] != '\n') {
                                log_debug("Failed to parse message, ignoring.");
                                break;
                        }

                        k = malloc((e - p) + 1 + l);
                        if (!k) {
                                log_oom();
                                break;
                        }

                        memcpy(k, p, e - p);
                        k[e - p] = '=';
                        memcpy(k + (e - p) + 1, e + 1 + sizeof(uint64_t), l);

                        if (valid_user_field(p, e - p, false)) {
                                iovec[n].iov_base = k;
                                iovec[n].iov_len = (e - p) + 1 + l;
                                entry_size += iovec[n].iov_len;
                                n++;
                        } else
                                free(k);

                        remaining -= (e - p) + 1 + sizeof(uint64_t) + l + 1;
                        p = e + 1 + sizeof(uint64_t) + l + 1;
                }
        }

        if (n <= 0)
                goto finish;

        tn = n++;
        IOVEC_SET_STRING(iovec[tn], "_TRANSPORT=journal");
        entry_size += strlen("_TRANSPORT=journal");

        if (entry_size + n + 1 > ENTRY_SIZE_MAX) { /* data + separators + trailer */
                log_debug("Entry is too big with %u properties and %zu bytes, ignoring.",
                          n, entry_size);
                goto finish;
        }

        if (message) {
                if (s->forward_to_syslog)
                        server_forward_syslog(s, priority, identifier, message, ucred, tv);

                if (s->forward_to_kmsg)
                        server_forward_kmsg(s, priority, identifier, message, ucred);

                if (s->forward_to_console)
                        server_forward_console(s, priority, identifier, message, ucred);

                if (s->forward_to_wall)
                        server_forward_wall(s, priority, identifier, message, ucred);
        }

        server_dispatch_message(s, iovec, n, m, ucred, tv, label, label_len, NULL, priority, object_pid);

finish:
        for (j = 0; j < n; j++)  {
                if (j == tn)
                        continue;

                if (iovec[j].iov_base < buffer ||
                    (const uint8_t*) iovec[j].iov_base >= (const uint8_t*) buffer + buffer_size)
                        free(iovec[j].iov_base);
        }

        free(iovec);
        free(identifier);
        free(message);
}

void server_process_native_file(
                Server *s,
                int fd,
                const struct ucred *ucred,
                const struct timeval *tv,
                const char *label, size_t label_len) {

        struct stat st;
        bool sealed;
        int r;

        /* Data is in the passed fd, since it didn't fit in a
         * datagram. */

        assert(s);
        assert(fd >= 0);

        /* If it's a memfd, check if it is sealed. If so, we can just
         * use map it and use it, and do not need to copy the data
         * out. */
        sealed = memfd_get_sealed(fd) > 0;

        if (!sealed && (!ucred || ucred->uid != 0)) {
                _cleanup_free_ char *sl = NULL, *k = NULL;
                const char *e;

                /* If this is not a sealed memfd, and the peer is unknown or
                 * unprivileged, then verify the path. */

                if (asprintf(&sl, "/proc/self/fd/%i", fd) < 0) {
                        log_oom();
                        return;
                }

                r = readlink_malloc(sl, &k);
                if (r < 0) {
                        log_error_errno(r, "readlink(%s) failed: %m", sl);
                        return;
                }

                e = path_startswith(k, "/dev/shm/");
                if (!e)
                        e = path_startswith(k, "/tmp/");
                if (!e)
                        e = path_startswith(k, "/var/tmp/");
                if (!e) {
                        log_error("Received file outside of allowed directories. Refusing.");
                        return;
                }

                if (!filename_is_valid(e)) {
                        log_error("Received file in subdirectory of allowed directories. Refusing.");
                        return;
                }
        }

        if (fstat(fd, &st) < 0) {
                log_error_errno(errno, "Failed to stat passed file, ignoring: %m");
                return;
        }

        if (!S_ISREG(st.st_mode)) {
                log_error("File passed is not regular. Ignoring.");
                return;
        }

        if (st.st_size <= 0)
                return;

        if (st.st_size > ENTRY_SIZE_MAX) {
                log_error("File passed too large. Ignoring.");
                return;
        }

        if (sealed) {
                void *p;
                size_t ps;

                /* The file is sealed, we can just map it and use it. */

                ps = PAGE_ALIGN(st.st_size);
                p = mmap(NULL, ps, PROT_READ, MAP_PRIVATE, fd, 0);
                if (p == MAP_FAILED) {
                        log_error_errno(errno, "Failed to map memfd, ignoring: %m");
                        return;
                }

                server_process_native_message(s, p, st.st_size, ucred, tv, label, label_len);
                assert_se(munmap(p, ps) >= 0);
        } else {
                _cleanup_free_ void *p = NULL;
                struct statvfs vfs;
                ssize_t n;

                if (fstatvfs(fd, &vfs) < 0) {
                        log_error_errno(errno, "Failed to stat file system of passed file, ignoring: %m");
                        return;
                }

                /* Refuse operating on file systems that have
                 * mandatory locking enabled, see:
                 *
                 * https://github.com/systemd/systemd/issues/1822
                 */
                if (vfs.f_flag & ST_MANDLOCK) {
                        log_error("Received file descriptor from file system with mandatory locking enable, refusing.");
                        return;
                }

                /* Make the fd non-blocking. On regular files this has
                 * the effect of bypassing mandatory locking. Of
                 * course, this should normally not be necessary given
                 * the check above, but let's better be safe than
                 * sorry, after all NFS is pretty confusing regarding
                 * file system flags, and we better don't trust it,
                 * and so is SMB. */
                r = fd_nonblock(fd, true);
                if (r < 0) {
                        log_error_errno(r, "Failed to make fd non-blocking, ignoring: %m");
                        return;
                }

                /* The file is not sealed, we can't map the file here, since
                 * clients might then truncate it and trigger a SIGBUS for
                 * us. So let's stupidly read it */

                p = malloc(st.st_size);
                if (!p) {
                        log_oom();
                        return;
                }

                n = pread(fd, p, st.st_size, 0);
                if (n < 0)
                        log_error_errno(errno, "Failed to read file, ignoring: %m");
                else if (n > 0)
                        server_process_native_message(s, p, n, ucred, tv, label, label_len);
        }
}

int server_open_native_socket(Server*s) {
        static const int one = 1;
        int r;

        assert(s);

        if (s->native_fd < 0) {
                union sockaddr_union sa = {
                        .un.sun_family = AF_UNIX,
                        .un.sun_path = "/run/systemd/journal/socket",
                };

                s->native_fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (s->native_fd < 0)
                        return log_error_errno(errno, "socket() failed: %m");

                unlink(sa.un.sun_path);

                r = bind(s->native_fd, &sa.sa, offsetof(union sockaddr_union, un.sun_path) + strlen(sa.un.sun_path));
                if (r < 0)
                        return log_error_errno(errno, "bind(%s) failed: %m", sa.un.sun_path);

                (void) chmod(sa.un.sun_path, 0666);
        } else
                fd_nonblock(s->native_fd, 1);

        r = setsockopt(s->native_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        if (r < 0)
                return log_error_errno(errno, "SO_PASSCRED failed: %m");

#ifdef HAVE_SELINUX
        if (mac_selinux_use()) {
                r = setsockopt(s->native_fd, SOL_SOCKET, SO_PASSSEC, &one, sizeof(one));
                if (r < 0)
                        log_warning_errno(errno, "SO_PASSSEC failed: %m");
        }
#endif

        r = setsockopt(s->native_fd, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(one));
        if (r < 0)
                return log_error_errno(errno, "SO_TIMESTAMP failed: %m");

        r = sd_event_add_io(s->event, &s->native_event_source, s->native_fd, EPOLLIN, server_process_datagram, s);
        if (r < 0)
                return log_error_errno(r, "Failed to add native server fd to event loop: %m");

        return 0;
}
