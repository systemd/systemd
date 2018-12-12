/* SPDX-License-Identifier: LGPL-2.1+ */

#include <grp.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "def.h"
#include "errno.h"
#include "fd-util.h"
#include "fileio.h"
#include "mkdir.h"
#include "nspawn-setuid.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "util.h"

static int spawn_getent(const char *database, const char *key, pid_t *rpid) {
        int pipe_fds[2], r;
        pid_t pid;

        assert(database);
        assert(key);
        assert(rpid);

        if (pipe2(pipe_fds, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to allocate pipe: %m");

        r = safe_fork("(getent)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG, &pid);
        if (r < 0) {
                safe_close_pair(pipe_fds);
                return r;
        }
        if (r == 0) {
                char *empty_env = NULL;

                safe_close(pipe_fds[0]);

                if (rearrange_stdio(-1, pipe_fds[1], -1) < 0)
                        _exit(EXIT_FAILURE);

                close_all_fds(NULL, 0);

                (void) rlimit_nofile_safe();

                execle("/usr/bin/getent", "getent", database, key, NULL, &empty_env);
                execle("/bin/getent", "getent", database, key, NULL, &empty_env);
                _exit(EXIT_FAILURE);
        }

        pipe_fds[1] = safe_close(pipe_fds[1]);

        *rpid = pid;

        return pipe_fds[0];
}

int change_uid_gid(const char *user, char **_home) {
        char *x, *u, *g, *h;
        const char *word, *state;
        _cleanup_free_ uid_t *uids = NULL;
        _cleanup_free_ char *home = NULL, *line = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_close_ int fd = -1;
        unsigned n_uids = 0;
        size_t sz = 0, l;
        uid_t uid;
        gid_t gid;
        pid_t pid;
        int r;

        assert(_home);

        if (!user || STR_IN_SET(user, "root", "0")) {
                /* Reset everything fully to 0, just in case */

                r = reset_uid_gid();
                if (r < 0)
                        return log_error_errno(r, "Failed to become root: %m");

                *_home = NULL;
                return 0;
        }

        /* First, get user credentials */
        fd = spawn_getent("passwd", user, &pid);
        if (fd < 0)
                return fd;

        f = fdopen(fd, "r");
        if (!f)
                return log_oom();
        fd = -1;

        r = read_line(f, LONG_LINE_MAX, &line);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH),
                                       "Failed to resolve user %s.", user);
        if (r < 0)
                return log_error_errno(r, "Failed to read from getent: %m");

        (void) wait_for_terminate_and_check("getent passwd", pid, WAIT_LOG);

        x = strchr(line, ':');
        if (!x)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "/etc/passwd entry has invalid user field.");

        u = strchr(x+1, ':');
        if (!u)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "/etc/passwd entry has invalid password field.");

        u++;
        g = strchr(u, ':');
        if (!g)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "/etc/passwd entry has invalid UID field.");

        *g = 0;
        g++;
        x = strchr(g, ':');
        if (!x)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "/etc/passwd entry has invalid GID field.");

        *x = 0;
        h = strchr(x+1, ':');
        if (!h)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "/etc/passwd entry has invalid GECOS field.");

        h++;
        x = strchr(h, ':');
        if (!x)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "/etc/passwd entry has invalid home directory field.");

        *x = 0;

        r = parse_uid(u, &uid);
        if (r < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to parse UID of user.");

        r = parse_gid(g, &gid);
        if (r < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Failed to parse GID of user.");

        home = strdup(h);
        if (!home)
                return log_oom();

        f = safe_fclose(f);
        line = mfree(line);

        /* Second, get group memberships */
        fd = spawn_getent("initgroups", user, &pid);
        if (fd < 0)
                return fd;

        f = fdopen(fd, "r");
        if (!f)
                return log_oom();
        fd = -1;

        r = read_line(f, LONG_LINE_MAX, &line);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH),
                                       "Failed to resolve user %s.", user);
        if (r < 0)
                return log_error_errno(r, "Failed to read from getent: %m");

        (void) wait_for_terminate_and_check("getent initgroups", pid, WAIT_LOG);

        /* Skip over the username and subsequent separator whitespace */
        x = line;
        x += strcspn(x, WHITESPACE);
        x += strspn(x, WHITESPACE);

        FOREACH_WORD(word, l, x, state) {
                char c[l+1];

                memcpy(c, word, l);
                c[l] = 0;

                if (!GREEDY_REALLOC(uids, sz, n_uids+1))
                        return log_oom();

                r = parse_uid(c, &uids[n_uids++]);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse group data from getent: %m");
        }

        r = mkdir_parents(home, 0775);
        if (r < 0)
                return log_error_errno(r, "Failed to make home root directory: %m");

        r = mkdir_safe(home, 0755, uid, gid, 0);
        if (r < 0 && !IN_SET(r, -EEXIST, -ENOTDIR))
                return log_error_errno(r, "Failed to make home directory: %m");

        (void) fchown(STDIN_FILENO, uid, gid);
        (void) fchown(STDOUT_FILENO, uid, gid);
        (void) fchown(STDERR_FILENO, uid, gid);

        if (setgroups(n_uids, uids) < 0)
                return log_error_errno(errno, "Failed to set auxiliary groups: %m");

        if (setresgid(gid, gid, gid) < 0)
                return log_error_errno(errno, "setresgid() failed: %m");

        if (setresuid(uid, uid, uid) < 0)
                return log_error_errno(errno, "setresuid() failed: %m");

        if (_home)
                *_home = TAKE_PTR(home);

        return 0;
}
