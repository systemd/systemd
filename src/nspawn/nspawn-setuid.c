/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "constants.h"
#include "errno.h"
#include "fd-util.h"
#include "fileio.h"
#include "mkdir.h"
#include "nspawn-setuid.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

static int spawn_getent(const char *database, const char *key, pid_t *rpid) {
        int pipe_fds[2], r;
        pid_t pid;

        assert(database);
        assert(key);
        assert(rpid);

        if (pipe2(pipe_fds, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to allocate pipe: %m");

        r = safe_fork_full("(getent)",
                           (int[]) { -EBADF, pipe_fds[1], -EBADF }, NULL, 0,
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE,
                           &pid);
        if (r < 0) {
                safe_close_pair(pipe_fds);
                return r;
        }
        if (r == 0) {
                execle("/usr/bin/getent", "getent", database, key, NULL, &(char*[1]){});
                execle("/bin/getent", "getent", database, key, NULL, &(char*[1]){});
                _exit(EXIT_FAILURE);
        }

        pipe_fds[1] = safe_close(pipe_fds[1]);

        *rpid = pid;

        return pipe_fds[0];
}

int change_uid_gid_raw(
                uid_t uid,
                gid_t gid,
                const gid_t *supplementary_gids,
                size_t n_supplementary_gids,
                bool chown_stdio) {

        int r;

        if (!uid_is_valid(uid))
                uid = 0;
        if (!gid_is_valid(gid))
                gid = 0;

        if (chown_stdio) {
                (void) fchown(STDIN_FILENO, uid, gid);
                (void) fchown(STDOUT_FILENO, uid, gid);
                (void) fchown(STDERR_FILENO, uid, gid);
        }

        r = fully_set_uid_gid(uid, gid, supplementary_gids, n_supplementary_gids);
        if (r < 0)
                return log_error_errno(r, "Changing privileges failed: %m");

        return 0;
}

int change_uid_gid(const char *user, bool chown_stdio, char **ret_home) {
        char *x, *u, *g, *h;
        _cleanup_free_ gid_t *gids = NULL;
        _cleanup_free_ char *home = NULL, *line = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_close_ int fd = -EBADF;
        unsigned n_gids = 0;
        uid_t uid;
        gid_t gid;
        pid_t pid;
        int r;

        assert(ret_home);

        if (!user || STR_IN_SET(user, "root", "0")) {
                /* Reset everything fully to 0, just in case */

                r = reset_uid_gid();
                if (r < 0)
                        return log_error_errno(r, "Failed to become root: %m");

                *ret_home = NULL;
                return 0;
        }

        /* First, get user credentials */
        fd = spawn_getent("passwd", user, &pid);
        if (fd < 0)
                return fd;

        f = take_fdopen(&fd, "r");
        if (!f)
                return log_oom();

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

        f = take_fdopen(&fd, "r");
        if (!f)
                return log_oom();

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

        for (const char *p = x;;) {
               _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse group data from getent: %m");
                if (r == 0)
                        break;

                if (!GREEDY_REALLOC(gids, n_gids+1))
                        return log_oom();

                r = parse_gid(word, &gids[n_gids++]);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse group data from getent: %m");
        }

        r = mkdir_parents(home, 0775);
        if (r < 0)
                return log_error_errno(r, "Failed to make home root directory: %m");

        r = mkdir_safe(home, 0755, uid, gid, 0);
        if (r < 0 && !IN_SET(r, -EEXIST, -ENOTDIR))
                return log_error_errno(r, "Failed to make home directory: %m");

        r = change_uid_gid_raw(uid, gid, gids, n_gids, chown_stdio);
        if (r < 0)
                return r;

        if (ret_home)
                *ret_home = TAKE_PTR(home);

        return 0;
}
