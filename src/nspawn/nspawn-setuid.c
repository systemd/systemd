/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include <grp.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "mkdir.h"
#include "nspawn-setuid.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "user-util.h"
#include "util.h"

static int spawn_getent(const char *database, const char *key, pid_t *rpid) {
        int pipe_fds[2];
        pid_t pid;

        assert(database);
        assert(key);
        assert(rpid);

        if (pipe2(pipe_fds, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to allocate pipe: %m");

        pid = fork();
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork getent child: %m");
        else if (pid == 0) {
                int nullfd;
                char *empty_env = NULL;

                if (dup3(pipe_fds[1], STDOUT_FILENO, 0) < 0)
                        _exit(EXIT_FAILURE);

                if (pipe_fds[0] > 2)
                        safe_close(pipe_fds[0]);
                if (pipe_fds[1] > 2)
                        safe_close(pipe_fds[1]);

                nullfd = open("/dev/null", O_RDWR);
                if (nullfd < 0)
                        _exit(EXIT_FAILURE);

                if (dup3(nullfd, STDIN_FILENO, 0) < 0)
                        _exit(EXIT_FAILURE);

                if (dup3(nullfd, STDERR_FILENO, 0) < 0)
                        _exit(EXIT_FAILURE);

                if (nullfd > 2)
                        safe_close(nullfd);

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();
                close_all_fds(NULL, 0);

                execle("/usr/bin/getent", "getent", database, key, NULL, &empty_env);
                execle("/bin/getent", "getent", database, key, NULL, &empty_env);
                _exit(EXIT_FAILURE);
        }

        pipe_fds[1] = safe_close(pipe_fds[1]);

        *rpid = pid;

        return pipe_fds[0];
}

int change_uid_gid(const char *user, char **_home) {
        char line[LINE_MAX], *x, *u, *g, *h;
        const char *word, *state;
        _cleanup_free_ uid_t *uids = NULL;
        _cleanup_free_ char *home = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_close_ int fd = -1;
        unsigned n_uids = 0;
        size_t sz = 0, l;
        uid_t uid;
        gid_t gid;
        pid_t pid;
        int r;

        assert(_home);

        if (!user || streq(user, "root") || streq(user, "0")) {
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

        if (!fgets(line, sizeof(line), f)) {

                if (!ferror(f)) {
                        log_error("Failed to resolve user %s.", user);
                        return -ESRCH;
                }

                log_error_errno(errno, "Failed to read from getent: %m");
                return -errno;
        }

        truncate_nl(line);

        wait_for_terminate_and_warn("getent passwd", pid, true);

        x = strchr(line, ':');
        if (!x) {
                log_error("/etc/passwd entry has invalid user field.");
                return -EIO;
        }

        u = strchr(x+1, ':');
        if (!u) {
                log_error("/etc/passwd entry has invalid password field.");
                return -EIO;
        }

        u++;
        g = strchr(u, ':');
        if (!g) {
                log_error("/etc/passwd entry has invalid UID field.");
                return -EIO;
        }

        *g = 0;
        g++;
        x = strchr(g, ':');
        if (!x) {
                log_error("/etc/passwd entry has invalid GID field.");
                return -EIO;
        }

        *x = 0;
        h = strchr(x+1, ':');
        if (!h) {
                log_error("/etc/passwd entry has invalid GECOS field.");
                return -EIO;
        }

        h++;
        x = strchr(h, ':');
        if (!x) {
                log_error("/etc/passwd entry has invalid home directory field.");
                return -EIO;
        }

        *x = 0;

        r = parse_uid(u, &uid);
        if (r < 0) {
                log_error("Failed to parse UID of user.");
                return -EIO;
        }

        r = parse_gid(g, &gid);
        if (r < 0) {
                log_error("Failed to parse GID of user.");
                return -EIO;
        }

        home = strdup(h);
        if (!home)
                return log_oom();

        /* Second, get group memberships */
        fd = spawn_getent("initgroups", user, &pid);
        if (fd < 0)
                return fd;

        fclose(f);
        f = fdopen(fd, "r");
        if (!f)
                return log_oom();
        fd = -1;

        if (!fgets(line, sizeof(line), f)) {
                if (!ferror(f)) {
                        log_error("Failed to resolve user %s.", user);
                        return -ESRCH;
                }

                log_error_errno(errno, "Failed to read from getent: %m");
                return -errno;
        }

        truncate_nl(line);

        wait_for_terminate_and_warn("getent initgroups", pid, true);

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
                if (r < 0) {
                        log_error("Failed to parse group data from getent.");
                        return -EIO;
                }
        }

        r = mkdir_parents(home, 0775);
        if (r < 0)
                return log_error_errno(r, "Failed to make home root directory: %m");

        r = mkdir_safe(home, 0755, uid, gid);
        if (r < 0 && r != -EEXIST)
                return log_error_errno(r, "Failed to make home directory: %m");

        (void) fchown(STDIN_FILENO, uid, gid);
        (void) fchown(STDOUT_FILENO, uid, gid);
        (void) fchown(STDERR_FILENO, uid, gid);

        if (setgroups(n_uids, uids) < 0)
                return log_error_errno(errno, "Failed to set auxiliary groups: %m");

        if (setresgid(gid, gid, gid) < 0)
                return log_error_errno(errno, "setregid() failed: %m");

        if (setresuid(uid, uid, uid) < 0)
                return log_error_errno(errno, "setreuid() failed: %m");

        if (_home) {
                *_home = home;
                home = NULL;
        }

        return 0;
}
