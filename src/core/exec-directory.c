/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <limits.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "errno-util.h"
#include "exec-directory.h"
#include "execute.h"
#include "fs-util.h"
#include "iovec-util.h"
#include "manager.h"
#include "path-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "unit.h"
#include "unit-name.h"

/* Private datagram from systemd-executor, followed by the NUL-terminated unit name and the path. */
typedef struct DirectoryReport {
        sd_id128_t invocation_id;
        uint64_t dev, ino, type;
} DirectoryReport;

int exec_report_directory(const ExecParameters *p, ExecDirectoryType type, const char *path, const char *symlink_path) {
        struct stat st;

        assert(p);
        assert(type >= 0 && type < _EXEC_DIRECTORY_TYPE_MAX);
        assert(path);

        if (p->directory_report_fd < 0)
                return 0;

        /* Directories are set up on the host. For links, stat the link we actually set up, which may be
         * in the executor's mount namespace; the manager compares it with the host path. */
        if (lstat(symlink_path ?: path, &st) < 0)
                return errno == ENOENT ? 0 : -errno;
        if (symlink_path ? !S_ISLNK(st.st_mode) : !S_ISDIR(st.st_mode))
                return 0;

        DirectoryReport header = {
                .invocation_id = p->invocation_id,
                .dev = st.st_dev,
                .ino = st.st_ino,
                .type = type,
        };
        struct iovec iov[] = {
                IOVEC_MAKE(&header, sizeof(header)),
                IOVEC_MAKE((char*) p->unit_id, strlen(p->unit_id) + 1),
                IOVEC_MAKE_STRING(path),
        };
        return RET_NERRNO(writev(p->directory_report_fd, iov, ELEMENTSOF(iov)));
}

int unit_add_owned_directory(Unit *u, ExecDirectoryType type, const char *path) {
        assert(u);
        assert(path);

        if (type < 0 || type >= _EXEC_DIRECTORY_TYPE_MAX ||
            !u->manager->prefix[type] || !path_is_normalized(path))
                return -EINVAL;

        const char *suffix = path_startswith(path, u->manager->prefix[type]);
        if (isempty(suffix) || path_equal(suffix, "private"))
                return -EINVAL;

        if (strv_contains(u->owned_directories[type], path))
                return 0;

        return strv_extend(&u->owned_directories[type], path);
}

void unit_prune_owned_directories(Unit *u) {
        assert(u);

        /* Check even after an unsuccessful clean, since the worker may have removed some of the paths.
         * Do not follow links: a dangling symlink is still something the unit owns. */
        FOREACH_ELEMENT(d, u->owned_directories) {
                if (strv_isempty(*d))
                        continue;

                char **keep = *d;
                STRV_FOREACH(p, *d)
                        if (IN_SET(access_nofollow(*p, F_OK), -ENOENT, -ENOTDIR))
                                free(*p);
                        else
                                *keep++ = *p;
                *keep = NULL;
                if (strv_isempty(*d))
                        *d = mfree(*d);
        }
}

static int dispatch_directory_report(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        struct {
                DirectoryReport header;
                char data[UNIT_NAME_MAX + PATH_MAX + 1];
        } msg;
        struct stat st;
        int r;

        ssize_t n = recv(fd, &msg, sizeof(msg), MSG_DONTWAIT|MSG_TRUNC);
        if (n < 0)
                return ERRNO_IS_TRANSIENT(errno) ? 0 : log_error_errno(errno, "Failed to receive directory report: %m");
        if ((size_t) n <= sizeof(msg.header) || (size_t) n - sizeof(msg.header) >= sizeof(msg.data) ||
            msg.header.type >= _EXEC_DIRECTORY_TYPE_MAX)
                goto invalid;

        size_t len = n - sizeof(msg.header);
        msg.data[len] = 0;
        const char *separator = memchr(msg.data, 0, len);
        if (!separator)
                goto invalid;
        const char *path = separator + 1;
        if (path >= msg.data + len || memchr(path, 0, msg.data + len - path))
                goto invalid;

        Unit *u = manager_get_unit(m, msg.data);
        if (!u || !sd_id128_equal(u->invocation_id, msg.header.invocation_id))
                return 0; /* Stale, e.g. the unit became an alias of another running unit during reload. */

        /* A symlink created in a service's mount namespace may not be visible at this path on the host. */
        if (lstat(path, &st) < 0) {
                if (!IN_SET(errno, ENOENT, ENOTDIR))
                        log_unit_warning_errno(u, errno, "Failed to stat reported directory '%s', ignoring: %m", path);
                return 0;
        }
        if (msg.header.dev != st.st_dev || msg.header.ino != st.st_ino)
                return 0;

        r = unit_add_owned_directory(u, msg.header.type, path);
        if (r < 0)
                log_unit_warning_errno(u, r, "Failed to remember owned directory '%s', ignoring: %m", path);
        return 0;

invalid:
        log_warning("Received malformed executor directory report, ignoring.");
        return 0;
}

int manager_setup_directory_reports(Manager *m) {
        int r;

        assert(m);

        if (m->directory_report_event_source)
                return 0;

        /* Only the manager and its executors have access to this socket pair, never unit payloads. */
        if (m->directory_report_fds[0] < 0) {
                if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, m->directory_report_fds) < 0)
                        return -errno;

                r = setsockopt_int(m->directory_report_fds[0], SOL_SOCKET, SO_PASSRIGHTS, /* value= */ false);
                if (r < 0 && !ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_warning_errno(r, "Failed to turn off SO_PASSRIGHTS on directory report socket, ignoring: %m");
                (void) fd_increase_rxbuf(m->directory_report_fds[0], MANAGER_SOCKET_RCVBUF_SIZE);
        }

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_io(m->event, &s, m->directory_report_fds[0], EPOLLIN, dispatch_directory_report, m);
        if (r < 0)
                return r;

        /* Record the paths before SIGCHLD can release the unit's resources. */
        r = sd_event_source_set_priority(s, EVENT_PRIORITY_USER_LOOKUP);
        if (r < 0)
                return r;
        (void) sd_event_source_set_description(s, "exec-directory");
        m->directory_report_event_source = TAKE_PTR(s);
        return 0;
}
