/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <pwd.h>
#include <endian.h>

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>

#include <libcgroup.h>

#include "util.h"
#include "cgroup-util.h"
#include "macro.h"
#include "sd-daemon.h"

static int parse_argv(pam_handle_t *handle,
                      int argc, const char **argv,
                      bool *create_session,
                      bool *kill_session,
                      bool *kill_user) {

        unsigned i;

        assert(argc >= 0);
        assert(argc == 0 || argv);

        for (i = 0; i < (unsigned) argc; i++) {
                int k;

                if (startswith(argv[i], "create-session=")) {
                        if ((k = parse_boolean(argv[i] + 15)) < 0) {
                                pam_syslog(handle, LOG_ERR, "Failed to parse create-session= argument.");
                                return k;
                        }

                        if (create_session)
                                *create_session = k;
                } else if (startswith(argv[i], "kill-session=")) {
                        if ((k = parse_boolean(argv[i] + 13)) < 0) {
                                pam_syslog(handle, LOG_ERR, "Failed to parse kill-session= argument.");
                                return k;
                        }

                        if (kill_session)
                                *kill_session = k;

                } else if (startswith(argv[i], "kill-user=")) {
                        if ((k = parse_boolean(argv[i] + 10)) < 0) {
                                pam_syslog(handle, LOG_ERR, "Failed to parse kill-user= argument.");
                                return k;
                        }

                        if (kill_user)
                                *kill_user = k;
                } else {
                        pam_syslog(handle, LOG_ERR, "Unknown parameter '%s'.", argv[i]);
                        return -EINVAL;
                }
        }

        if (kill_session && *kill_session && kill_user)
                *kill_user = true;

        return 0;
}

static int open_file_and_lock(const char *fn) {
        int fd;

        assert(fn);

        if ((fd = open(fn, O_RDWR|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW|O_CREAT, 0600)) < 0)
                return -errno;

        /* The BSD socket semantics are a lot nicer than those of
         * POSIX locks. Which is why we use flock() here. BSD locking
         * does not work across NFS which however is not needed here
         * as the filesystems in question should be local, and only
         * locally accessible, and most likely even tmpfs. */

        if (flock(fd, LOCK_EX) < 0)
                return -errno;

        return fd;
}

enum {
        SESSION_ID_AUDIT = 'a',
        SESSION_ID_COUNTER = 'c',
        SESSION_ID_RANDOM = 'r'
};

static uint64_t get_session_id(int *mode) {
        char *s;
        int fd;

        assert(mode);

        /* First attempt: let's use the session ID of the audit
         * system, if it is available. */
        if (read_one_line_file("/proc/self/sessionid", &s) >= 0) {
                uint32_t u;
                int r;

                r = safe_atou32(s, &u);
                free(s);

                if (r >= 0 && u != (uint32_t) -1) {
                        *mode = SESSION_ID_AUDIT;
                        return (uint64_t) u;
                }
        }

        /* Second attempt, use our own counter. */
        if ((fd = open_file_and_lock(RUNTIME_DIR "/user/.pam-systemd-session")) >= 0) {
                uint64_t counter;
                ssize_t r;

                /* We do a bit of endianess swapping here, just to be
                 * sure. /var should be machine specific anyway, and
                 * /var/run even mounted from tmpfs, so this
                 * byteswapping should really not be necessary. But
                 * then again, you never know, so let's avoid any
                 * risk. */

                if (loop_read(fd, &counter, sizeof(counter), false) != sizeof(counter))
                        counter = 1;
                else
                        counter = le64toh(counter) + 1;

                if (lseek(fd, 0, SEEK_SET) == 0) {
                        uint64_t swapped = htole64(counter);

                        r = loop_write(fd, &swapped, sizeof(swapped), false);

                        if (r != sizeof(swapped))
                                r = -EIO;
                } else
                        r = -errno;

                close_nointr_nofail(fd);

                if (r >= 0) {
                        *mode = SESSION_ID_COUNTER;
                        return counter;
                }
        }

        *mode = SESSION_ID_RANDOM;

        /* Last attempt, pick a random value */
        return (uint64_t) random_ull();
}
static int get_user_data(
                pam_handle_t *handle,
                const char **ret_username,
                struct passwd **ret_pw) {

        const char *username;
        struct passwd *pw;
        int r;

        assert(handle);
        assert(ret_username);
        assert(ret_pw);

        if ((r = pam_get_user(handle, &username, NULL)) != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to get user name.");
                return r;
        }

        if (!username || !*username) {
                pam_syslog(handle, LOG_ERR, "User name not valid.");
                return PAM_AUTH_ERR;
        }

        if (!(pw = pam_modutil_getpwnam(handle, username))) {
                pam_syslog(handle, LOG_ERR, "Failed to get user data.");
                return PAM_USER_UNKNOWN;
        }

        *ret_pw = pw;
        *ret_username = username;

        return PAM_SUCCESS;
}

static int create_user_group(pam_handle_t *handle, const char *group, struct passwd *pw, bool attach) {
        int r;

        assert(handle);
        assert(group);

        if (attach)
                r = cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, group, 0);
        else
                r = cg_create(SYSTEMD_CGROUP_CONTROLLER, group);

        if (r < 0) {
                pam_syslog(handle, LOG_ERR, "Failed to create cgroup: %s", strerror(-r));
                return PAM_SESSION_ERR;
        }

        if ((r = cg_set_task_access(SYSTEMD_CGROUP_CONTROLLER, group, 0755, pw->pw_uid, pw->pw_gid)) < 0 ||
            (r = cg_set_group_access(SYSTEMD_CGROUP_CONTROLLER, group, 0755, pw->pw_uid, pw->pw_gid)) < 0) {
                pam_syslog(handle, LOG_ERR, "Failed to change access modes: %s", strerror(-r));
                return PAM_SESSION_ERR;
        }

        return PAM_SUCCESS;
}

_public_ PAM_EXTERN int pam_sm_open_session(
                pam_handle_t *handle,
                int flags,
                int argc, const char **argv) {

        const char *username = NULL;
        struct passwd *pw;
        int r;
        char *buf = NULL;
        int lock_fd = -1;
        bool create_session = true;

        assert(handle);

        pam_syslog(handle, LOG_INFO, "pam-systemd initializing");

        if (parse_argv(handle, argc, argv, &create_session, NULL, NULL) < 0)
                return PAM_SESSION_ERR;

        /* Make this a NOP on non-systemd systems */
        if (sd_booted() <= 0)
                return PAM_SUCCESS;

        if ((r = cg_init()) < 0) {
                pam_syslog(handle, LOG_ERR, "libcgroup initialization failed: %s", strerror(-r));
                r = PAM_SESSION_ERR;
                goto finish;
        }

        if ((r = get_user_data(handle, &username, &pw)) != PAM_SUCCESS)
                goto finish;

        if (safe_mkdir(RUNTIME_DIR "/user", 0755, 0, 0) < 0) {
                pam_syslog(handle, LOG_ERR, "Failed to create runtime directory: %m");
                r = PAM_SYSTEM_ERR;
                goto finish;
        }

        if ((lock_fd = open_file_and_lock(RUNTIME_DIR "/user/.pam-systemd-lock")) < 0) {
                pam_syslog(handle, LOG_ERR, "Failed to lock runtime directory: %m");
                r = PAM_SYSTEM_ERR;
                goto finish;
        }

        /* Create /var/run/$USER */
        free(buf);
        if (asprintf(&buf, RUNTIME_DIR "/user/%s", username) < 0) {
                r = PAM_BUF_ERR;
                goto finish;
        }

        if (safe_mkdir(buf, 0700, pw->pw_uid, pw->pw_gid) < 0) {
                pam_syslog(handle, LOG_WARNING, "Failed to create runtime directory: %m");
                r = PAM_SYSTEM_ERR;
                goto finish;
        } else if ((r = pam_misc_setenv(handle, "XDG_RUNTIME_DIR", buf, 0)) != PAM_SUCCESS) {
                pam_syslog(handle, LOG_ERR, "Failed to set runtime dir.");
                goto finish;
        }

        free(buf);
        buf = NULL;

        if (create_session) {
                const char *id;

                /* Reuse or create XDG session ID */
                if (!(id = pam_getenv(handle, "XDG_SESSION_ID"))) {
                        int mode;

                        if (asprintf(&buf, "%llux", (unsigned long long) get_session_id(&mode)) < 0) {
                                r = PAM_BUF_ERR;
                                goto finish;
                        }

                        /* To avoid id clashes we add the session id
                         * source to our session ids. Note that the
                         * session id source might change during
                         * runtime, because a filesystem became
                         * writable or the system reconfigured. */
                        buf[strlen(buf)-1] =
                                mode != SESSION_ID_AUDIT ? (char) mode : 0;

                        if ((r = pam_misc_setenv(handle, "XDG_SESSION_ID", buf, 0)) != PAM_SUCCESS) {
                                pam_syslog(handle, LOG_ERR, "Failed to set session id.");
                                goto finish;
                        }

                        if (!(id = pam_getenv(handle, "XDG_SESSION_ID"))) {
                                pam_syslog(handle, LOG_ERR, "Failed to get session id.");
                                r = PAM_SESSION_ERR;
                                goto finish;
                        }
                }

                r = asprintf(&buf, "/user/%s/%s", username, id);
        } else
                r = asprintf(&buf, "/user/%s/no-session", username);

        if (r < 0) {
                r = PAM_BUF_ERR;
                goto finish;
        }

        if ((r = create_user_group(handle, buf, pw, true)) != PAM_SUCCESS)
                goto finish;

        r = PAM_SUCCESS;

finish:
        free(buf);

        if (lock_fd >= 0)
                close_nointr_nofail(lock_fd);

        return r;
}

static int session_remains(pam_handle_t *handle, const char *user_path) {
        struct cgroup_file_info info;
        int level = 0, r;
        void *iterator = NULL;
        bool remains = false;

        zero(info);

        r = cgroup_walk_tree_begin(SYSTEMD_CGROUP_CONTROLLER, user_path, 0, &iterator, &info, &level);
        while (r == 0) {

                if (info.type != CGROUP_FILE_TYPE_DIR)
                        goto next;

                if (streq(info.path, ""))
                        goto next;

                if (streq(info.path, "no-session"))
                        goto next;

                remains = true;
                break;

        next:

                r = cgroup_walk_tree_next(0, &iterator, &info, level);
        }


        if (remains)
                r = 1;
        else if (r == 0 || r == ECGEOF)
                r = 0;
        else
                r = cg_translate_error(r, errno);

        assert_se(cgroup_walk_tree_end(&iterator) == 0);

        return r;
}

_public_ PAM_EXTERN int pam_sm_close_session(
                pam_handle_t *handle,
                int flags,
                int argc, const char **argv) {

        const char *username = NULL;
        bool kill_session = false;
        bool kill_user = false;
        int lock_fd = -1, r;
        char *session_path = NULL, *nosession_path = NULL, *user_path = NULL;
        const char *id;
        struct passwd *pw;

        assert(handle);

        if (parse_argv(handle, argc, argv, NULL, &kill_session, &kill_user) < 0)
                return PAM_SESSION_ERR;

        /* Make this a NOP on non-systemd systems */
        if (sd_booted() <= 0)
                return PAM_SUCCESS;

        if ((r = get_user_data(handle, &username, &pw)) != PAM_SUCCESS)
                goto finish;

        if ((lock_fd = open_file_and_lock(RUNTIME_DIR "/user/.pam-systemd-lock")) < 0) {
                pam_syslog(handle, LOG_ERR, "Failed to lock runtime directory: %m");
                r = PAM_SYSTEM_ERR;
                goto finish;
        }

        if (asprintf(&user_path, "/user/%s", username) < 0) {
                r = PAM_BUF_ERR;
                goto finish;
        }

        if ((id = pam_getenv(handle, "XDG_SESSION_ID"))) {

                if (asprintf(&session_path, "/user/%s/%s", username, id) < 0 ||
                    asprintf(&nosession_path, "/user/%s/no-session", username) < 0) {
                        r = PAM_BUF_ERR;
                        goto finish;
                }

                if (kill_session)  {
                        /* Kill processes in session cgroup */
                        if ((r = cg_kill_recursive_and_wait(SYSTEMD_CGROUP_CONTROLLER, session_path)) < 0)
                                pam_syslog(handle, LOG_ERR, "Failed to kill session cgroup: %s", strerror(-r));

                } else  {
                        /* Migrate processes from session to
                         * no-session cgroup. First, try to create the
                         * no-session group in case it doesn't exist
                         * yet. */
                        create_user_group(handle, nosession_path, pw, 0);

                        if ((r = cg_migrate_recursive(SYSTEMD_CGROUP_CONTROLLER, session_path, nosession_path, false)) < 0)
                                pam_syslog(handle, LOG_ERR, "Failed to migrate session cgroup: %s", strerror(-r));
                }

                /* Delete session cgroup */
                if (r < 0)
                        pam_syslog(handle, LOG_INFO, "Couldn't empty session cgroup, not deleting.");
                else {
                        if ((r = cg_delete(SYSTEMD_CGROUP_CONTROLLER, session_path)) < 0)
                                pam_syslog(handle, LOG_ERR, "Failed to delete session cgroup: %s", strerror(-r));
                }
        }

        /* GC user tree */
        cg_trim(SYSTEMD_CGROUP_CONTROLLER, user_path, false);

        if ((r = session_remains(handle, user_path)) < 0)
                pam_syslog(handle, LOG_ERR, "Failed to determine whether a session remains: %s", strerror(-r));

        /* Kill user processes not attached to any session */
        if (kill_user && r == 0) {

                /* Kill no-session cgroup */
                if ((r = cg_kill_recursive_and_wait(SYSTEMD_CGROUP_CONTROLLER, user_path)) < 0)
                        pam_syslog(handle, LOG_ERR, "Failed to kill user cgroup: %s", strerror(-r));
        } else {

                if ((r = cg_is_empty_recursive(SYSTEMD_CGROUP_CONTROLLER, user_path, true)) < 0)
                        pam_syslog(handle, LOG_ERR, "Failed to check user cgroup: %s", strerror(-r));

                /* If we managed to kill somebody, don't cleanup the cgroup. */
                if (r == 0)
                        r = -EBUSY;
        }

        if (r >= 0) {
                const char *runtime_dir;

                /* Remove user cgroup */
                if ((r = cg_delete(SYSTEMD_CGROUP_CONTROLLER, user_path)) < 0)
                        pam_syslog(handle, LOG_ERR, "Failed to delete user cgroup: %s", strerror(-r));

                /* This will migrate us to the /user cgroup. */

                if ((runtime_dir = pam_getenv(handle, "XDG_RUNTIME_DIR")))
                        if ((r = rm_rf(runtime_dir, false, true)) < 0)
                                pam_syslog(handle, LOG_ERR, "Failed to remove runtime directory: %s", strerror(-r));
        }

        r = PAM_SUCCESS;

finish:
        if (lock_fd >= 0)
                close_nointr_nofail(lock_fd);

        free(session_path);
        free(nosession_path);
        free(user_path);

        return r;
}
