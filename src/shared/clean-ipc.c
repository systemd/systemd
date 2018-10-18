/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mqueue.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <unistd.h>

#include "clean-ipc.h"
#include "def.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "log.h"
#include "macro.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

static bool match_uid_gid(uid_t subject_uid, gid_t subject_gid, uid_t delete_uid, gid_t delete_gid) {

        if (uid_is_valid(delete_uid) && subject_uid == delete_uid)
                return true;

        if (gid_is_valid(delete_gid) && subject_gid == delete_gid)
                return true;

        return false;
}

static int clean_sysvipc_shm(uid_t delete_uid, gid_t delete_gid, bool rm) {
        _cleanup_fclose_ FILE *f = NULL;
        bool first = true;
        int ret = 0, r;

        f = fopen("/proc/sysvipc/shm", "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to open /proc/sysvipc/shm: %m");
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;
                unsigned n_attached;
                pid_t cpid, lpid;
                uid_t uid, cuid;
                gid_t gid, cgid;
                int shmid;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_warning_errno(errno, "Failed to read /proc/sysvipc/shm: %m");
                if (r == 0)
                        break;

                if (first) {
                        first = false;
                        continue;
                }

                if (sscanf(line, "%*i %i %*o %*u " PID_FMT " " PID_FMT " %u " UID_FMT " " GID_FMT " " UID_FMT " " GID_FMT,
                           &shmid, &cpid, &lpid, &n_attached, &uid, &gid, &cuid, &cgid) != 8)
                        continue;

                if (n_attached > 0)
                        continue;

                if (!match_uid_gid(uid, gid, delete_uid, delete_gid))
                        continue;

                if (!rm)
                        return 1;

                if (shmctl(shmid, IPC_RMID, NULL) < 0) {

                        /* Ignore entries that are already deleted */
                        if (IN_SET(errno, EIDRM, EINVAL))
                                continue;

                        ret = log_warning_errno(errno,
                                                "Failed to remove SysV shared memory segment %i: %m",
                                                shmid);
                } else {
                        log_debug("Removed SysV shared memory segment %i.", shmid);
                        if (ret == 0)
                                ret = 1;
                }
        }

        return ret;
}

static int clean_sysvipc_sem(uid_t delete_uid, gid_t delete_gid, bool rm) {
        _cleanup_fclose_ FILE *f = NULL;
        bool first = true;
        int ret = 0, r;

        f = fopen("/proc/sysvipc/sem", "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to open /proc/sysvipc/sem: %m");
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;
                uid_t uid, cuid;
                gid_t gid, cgid;
                int semid;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_warning_errno(r, "Failed to read /proc/sysvipc/sem: %m");
                if (r == 0)
                        break;

                if (first) {
                        first = false;
                        continue;
                }

                if (sscanf(line, "%*i %i %*o %*u " UID_FMT " " GID_FMT " " UID_FMT " " GID_FMT,
                           &semid, &uid, &gid, &cuid, &cgid) != 5)
                        continue;

                if (!match_uid_gid(uid, gid, delete_uid, delete_gid))
                        continue;

                if (!rm)
                        return 1;

                if (semctl(semid, 0, IPC_RMID) < 0) {

                        /* Ignore entries that are already deleted */
                        if (IN_SET(errno, EIDRM, EINVAL))
                                continue;

                        ret = log_warning_errno(errno,
                                                "Failed to remove SysV semaphores object %i: %m",
                                                semid);
                } else {
                        log_debug("Removed SysV semaphore %i.", semid);
                        if (ret == 0)
                                ret = 1;
                }
        }

        return ret;
}

static int clean_sysvipc_msg(uid_t delete_uid, gid_t delete_gid, bool rm) {
        _cleanup_fclose_ FILE *f = NULL;
        bool first = true;
        int ret = 0, r;

        f = fopen("/proc/sysvipc/msg", "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to open /proc/sysvipc/msg: %m");
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;
                uid_t uid, cuid;
                gid_t gid, cgid;
                pid_t cpid, lpid;
                int msgid;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_warning_errno(r, "Failed to read /proc/sysvipc/msg: %m");
                if (r == 0)
                        break;

                if (first) {
                        first = false;
                        continue;
                }

                if (sscanf(line, "%*i %i %*o %*u %*u " PID_FMT " " PID_FMT " " UID_FMT " " GID_FMT " " UID_FMT " " GID_FMT,
                           &msgid, &cpid, &lpid, &uid, &gid, &cuid, &cgid) != 7)
                        continue;

                if (!match_uid_gid(uid, gid, delete_uid, delete_gid))
                        continue;

                if (!rm)
                        return 1;

                if (msgctl(msgid, IPC_RMID, NULL) < 0) {

                        /* Ignore entries that are already deleted */
                        if (IN_SET(errno, EIDRM, EINVAL))
                                continue;

                        ret = log_warning_errno(errno,
                                                "Failed to remove SysV message queue %i: %m",
                                                msgid);
                } else {
                        log_debug("Removed SysV message queue %i.", msgid);
                        if (ret == 0)
                                ret = 1;
                }
        }

        return ret;
}

static int clean_posix_shm_internal(DIR *dir, uid_t uid, gid_t gid, bool rm) {
        struct dirent *de;
        int ret = 0, r;

        assert(dir);

        FOREACH_DIRENT_ALL(de, dir, goto fail) {
                struct stat st;

                if (dot_or_dot_dot(de->d_name))
                        continue;

                if (fstatat(dirfd(dir), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                        if (errno == ENOENT)
                                continue;

                        ret = log_warning_errno(errno, "Failed to stat() POSIX shared memory segment %s: %m", de->d_name);
                        continue;
                }

                if (S_ISDIR(st.st_mode)) {
                        _cleanup_closedir_ DIR *kid;

                        kid = xopendirat(dirfd(dir), de->d_name, O_NOFOLLOW|O_NOATIME);
                        if (!kid) {
                                if (errno != ENOENT)
                                        ret = log_warning_errno(errno, "Failed to enter shared memory directory %s: %m", de->d_name);
                        } else {
                                r = clean_posix_shm_internal(kid, uid, gid, rm);
                                if (r < 0)
                                        ret = r;
                        }

                        if (!match_uid_gid(st.st_uid, st.st_gid, uid, gid))
                                continue;

                        if (!rm)
                                return 1;

                        if (unlinkat(dirfd(dir), de->d_name, AT_REMOVEDIR) < 0) {

                                if (errno == ENOENT)
                                        continue;

                                ret = log_warning_errno(errno, "Failed to remove POSIX shared memory directory %s: %m", de->d_name);
                        } else {
                                log_debug("Removed POSIX shared memory directory %s", de->d_name);
                                if (ret == 0)
                                        ret = 1;
                        }
                } else {

                        if (!match_uid_gid(st.st_uid, st.st_gid, uid, gid))
                                continue;

                        if (!rm)
                                return 1;

                        if (unlinkat(dirfd(dir), de->d_name, 0) < 0) {

                                if (errno == ENOENT)
                                        continue;

                                ret = log_warning_errno(errno, "Failed to remove POSIX shared memory segment %s: %m", de->d_name);
                        } else {
                                log_debug("Removed POSIX shared memory segment %s", de->d_name);
                                if (ret == 0)
                                        ret = 1;
                        }
                }
        }

        return ret;

fail:
        return log_warning_errno(errno, "Failed to read /dev/shm: %m");
}

static int clean_posix_shm(uid_t uid, gid_t gid, bool rm) {
        _cleanup_closedir_ DIR *dir = NULL;

        dir = opendir("/dev/shm");
        if (!dir) {
                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to open /dev/shm: %m");
        }

        return clean_posix_shm_internal(dir, uid, gid, rm);
}

static int clean_posix_mq(uid_t uid, gid_t gid, bool rm) {
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *de;
        int ret = 0;

        dir = opendir("/dev/mqueue");
        if (!dir) {
                if (errno == ENOENT)
                        return 0;

                return log_warning_errno(errno, "Failed to open /dev/mqueue: %m");
        }

        FOREACH_DIRENT_ALL(de, dir, goto fail) {
                struct stat st;
                char fn[1+strlen(de->d_name)+1];

                if (dot_or_dot_dot(de->d_name))
                        continue;

                if (fstatat(dirfd(dir), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                        if (errno == ENOENT)
                                continue;

                        ret = log_warning_errno(errno,
                                                "Failed to stat() MQ segment %s: %m",
                                                de->d_name);
                        continue;
                }

                if (!match_uid_gid(st.st_uid, st.st_gid, uid, gid))
                        continue;

                if (!rm)
                        return 1;

                fn[0] = '/';
                strcpy(fn+1, de->d_name);

                if (mq_unlink(fn) < 0) {
                        if (errno == ENOENT)
                                continue;

                        ret = log_warning_errno(errno,
                                                "Failed to unlink POSIX message queue %s: %m",
                                                fn);
                } else {
                        log_debug("Removed POSIX message queue %s", fn);
                        if (ret == 0)
                                ret = 1;
                }
        }

        return ret;

fail:
        return log_warning_errno(errno, "Failed to read /dev/mqueue: %m");
}

int clean_ipc_internal(uid_t uid, gid_t gid, bool rm) {
        int ret = 0, r;

        /* If 'rm' is true, clean all IPC objects owned by either the specified UID or the specified GID. Return the
         * last error encountered or == 0 if no matching IPC objects have been found or > 0 if matching IPC objects
         * have been found and have been removed.
         *
         * If 'rm' is false, just search for IPC objects owned by either the specified UID or the specified GID. In
         * this case we return < 0 on error, > 0 if we found a matching object, == 0 if we didn't.
         *
         * As special rule: if UID/GID is specified as root we'll silently not clean up things, and always claim that
         * there are IPC objects for it. */

        if (uid == 0) {
                if (!rm)
                        return 1;

                uid = UID_INVALID;
        }
        if (gid == 0) {
                if (!rm)
                        return 1;

                gid = GID_INVALID;
        }

        /* Anything to do? */
        if (!uid_is_valid(uid) && !gid_is_valid(gid))
                return 0;

        r = clean_sysvipc_shm(uid, gid, rm);
        if (r != 0) {
                if (!rm)
                        return r;
                if (ret == 0)
                        ret = r;
        }

        r = clean_sysvipc_sem(uid, gid, rm);
        if (r != 0) {
                if (!rm)
                        return r;
                if (ret == 0)
                        ret = r;
        }

        r = clean_sysvipc_msg(uid, gid, rm);
        if (r != 0) {
                if (!rm)
                        return r;
                if (ret == 0)
                        ret = r;
        }

        r = clean_posix_shm(uid, gid, rm);
        if (r != 0) {
                if (!rm)
                        return r;
                if (ret == 0)
                        ret = r;
        }

        r = clean_posix_mq(uid, gid, rm);
        if (r != 0) {
                if (!rm)
                        return r;
                if (ret == 0)
                        ret = r;
        }

        return ret;
}

int clean_ipc_by_uid(uid_t uid) {
        return clean_ipc_internal(uid, GID_INVALID, true);
}

int clean_ipc_by_gid(gid_t gid) {
        return clean_ipc_internal(UID_INVALID, gid, true);
}
