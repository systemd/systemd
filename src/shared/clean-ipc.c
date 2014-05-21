/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <dirent.h>
#include <mqueue.h>

#include "util.h"
#include "strv.h"
#include "clean-ipc.h"

static int clean_sysvipc_shm(uid_t delete_uid) {
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX];
        bool first = true;
        int ret = 0;

        f = fopen("/proc/sysvipc/shm", "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                log_warning("Failed to open /proc/sysvipc/shm: %m");
                return -errno;
        }

        FOREACH_LINE(line, f, goto fail) {
                unsigned n_attached;
                pid_t cpid, lpid;
                uid_t uid, cuid;
                gid_t gid, cgid;
                int shmid;

                if (first) {
                        first = false;
                        continue;
                }

                truncate_nl(line);

                if (sscanf(line, "%*i %i %*o %*u " PID_FMT " " PID_FMT " %u " UID_FMT " " GID_FMT " " UID_FMT " " GID_FMT,
                           &shmid, &cpid, &lpid, &n_attached, &uid, &gid, &cuid, &cgid) != 8)
                        continue;

                if (n_attached > 0)
                        continue;

                if (uid != delete_uid)
                        continue;

                if (shmctl(shmid, IPC_RMID, NULL) < 0) {

                        /* Ignore entries that are already deleted */
                        if (errno == EIDRM || errno == EINVAL)
                                continue;

                        log_warning("Failed to remove SysV shared memory segment %i: %m", shmid);
                        ret = -errno;
                }
        }

        return ret;

fail:
        log_warning("Failed to read /proc/sysvipc/shm: %m");
        return -errno;
}

static int clean_sysvipc_sem(uid_t delete_uid) {
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX];
        bool first = true;
        int ret = 0;

        f = fopen("/proc/sysvipc/sem", "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                log_warning("Failed to open /proc/sysvipc/sem: %m");
                return -errno;
        }

        FOREACH_LINE(line, f, goto fail) {
                uid_t uid, cuid;
                gid_t gid, cgid;
                int semid;

                if (first) {
                        first = false;
                        continue;
                }

                truncate_nl(line);

                if (sscanf(line, "%*i %i %*o %*u " UID_FMT " " GID_FMT " " UID_FMT " " GID_FMT,
                           &semid, &uid, &gid, &cuid, &cgid) != 5)
                        continue;

                if (uid != delete_uid)
                        continue;

                if (semctl(semid, 0, IPC_RMID) < 0) {

                        /* Ignore entries that are already deleted */
                        if (errno == EIDRM || errno == EINVAL)
                                continue;

                        log_warning("Failed to remove SysV semaphores object %i: %m", semid);
                        ret = -errno;
                }
        }

        return ret;

fail:
        log_warning("Failed to read /proc/sysvipc/sem: %m");
        return -errno;
}

static int clean_sysvipc_msg(uid_t delete_uid) {
        _cleanup_fclose_ FILE *f = NULL;
        char line[LINE_MAX];
        bool first = true;
        int ret = 0;

        f = fopen("/proc/sysvipc/msg", "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                log_warning("Failed to open /proc/sysvipc/msg: %m");
                return -errno;
        }

        FOREACH_LINE(line, f, goto fail) {
                uid_t uid, cuid;
                gid_t gid, cgid;
                pid_t cpid, lpid;
                int msgid;

                if (first) {
                        first = false;
                        continue;
                }

                truncate_nl(line);

                if (sscanf(line, "%*i %i %*o %*u %*u " PID_FMT " " PID_FMT " " UID_FMT " " GID_FMT " " UID_FMT " " GID_FMT,
                           &msgid, &cpid, &lpid, &uid, &gid, &cuid, &cgid) != 7)
                        continue;

                if (uid != delete_uid)
                        continue;

                if (msgctl(msgid, IPC_RMID, NULL) < 0) {

                        /* Ignore entries that are already deleted */
                        if (errno == EIDRM || errno == EINVAL)
                                continue;

                        log_warning("Failed to remove SysV message queue %i: %m", msgid);
                        ret = -errno;
                }
        }

        return ret;

fail:
        log_warning("Failed to read /proc/sysvipc/msg: %m");
        return -errno;
}

static int clean_posix_shm_internal(DIR *dir, uid_t uid) {
        struct dirent *de;
        int ret = 0, r;

        assert(dir);

        FOREACH_DIRENT(de, dir, goto fail) {
                struct stat st;

                if (STR_IN_SET(de->d_name, "..", "."))
                        continue;

                if (fstatat(dirfd(dir), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                        if (errno == ENOENT)
                                continue;

                        log_warning("Failed to stat() POSIX shared memory segment %s: %m", de->d_name);
                        ret = -errno;
                        continue;
                }

                if (st.st_uid != uid)
                        continue;

                if (S_ISDIR(st.st_mode)) {
                        _cleanup_closedir_ DIR *kid;

                        kid = xopendirat(dirfd(dir), de->d_name, O_NOFOLLOW|O_NOATIME);
                        if (!kid) {
                                if (errno != ENOENT) {
                                        log_warning("Failed to enter shared memory directory %s: %m", de->d_name);
                                        ret = -errno;
                                }
                        } else {
                                r = clean_posix_shm_internal(kid, uid);
                                if (r < 0)
                                        ret = r;
                        }

                        if (unlinkat(dirfd(dir), de->d_name, AT_REMOVEDIR) < 0) {

                                if (errno == ENOENT)
                                        continue;

                                log_warning("Failed to remove POSIX shared memory directory %s: %m", de->d_name);
                                ret = -errno;
                        }
                } else {

                        if (unlinkat(dirfd(dir), de->d_name, 0) < 0) {

                                if (errno == ENOENT)
                                        continue;

                                log_warning("Failed to remove POSIX shared memory segment %s: %m", de->d_name);
                                ret = -errno;
                        }
                }
        }

        return ret;

fail:
        log_warning("Failed to read /dev/shm: %m");
        return -errno;
}

static int clean_posix_shm(uid_t uid) {
        _cleanup_closedir_ DIR *dir = NULL;

        dir = opendir("/dev/shm");
        if (!dir) {
                if (errno == ENOENT)
                        return 0;

                log_warning("Failed to open /dev/shm: %m");
                return -errno;
        }

        return clean_posix_shm_internal(dir, uid);
}

static int clean_posix_mq(uid_t uid) {
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *de;
        int ret = 0;

        dir = opendir("/dev/mqueue");
        if (!dir) {
                if (errno == ENOENT)
                        return 0;

                log_warning("Failed to open /dev/mqueue: %m");
                return -errno;
        }

        FOREACH_DIRENT(de, dir, goto fail) {
                struct stat st;
                char fn[1+strlen(de->d_name)+1];

                if (STR_IN_SET(de->d_name, "..", "."))
                        continue;

                if (fstatat(dirfd(dir), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                        if (errno == ENOENT)
                                continue;

                        log_warning("Failed to stat() MQ segment %s: %m", de->d_name);
                        ret = -errno;
                        continue;
                }

                if (st.st_uid != uid)
                        continue;

                fn[0] = '/';
                strcpy(fn+1, de->d_name);

                if (mq_unlink(fn) < 0) {
                        if (errno == ENOENT)
                                continue;

                        log_warning("Failed to unlink POSIX message queue %s: %m", fn);
                        ret = -errno;
                }
        }

        return ret;

fail:
        log_warning("Failed to read /dev/mqueue: %m");
        return -errno;
}

int clean_ipc(uid_t uid) {
        int ret = 0, r;

        /* Refuse to clean IPC of the root and system users */
        if (uid <= SYSTEM_UID_MAX)
                return 0;

        r = clean_sysvipc_shm(uid);
        if (r < 0)
                ret = r;

        r = clean_sysvipc_sem(uid);
        if (r < 0)
                ret = r;

        r = clean_sysvipc_msg(uid);
        if (r < 0)
                ret = r;

        r = clean_posix_shm(uid);
        if (r < 0)
                ret = r;

        r = clean_posix_mq(uid);
        if (r < 0)
                ret = r;

        return ret;
}
