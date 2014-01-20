/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <errno.h>
#include <sys/mount.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sched.h>
#include <sys/syscall.h>
#include <limits.h>
#include <linux/fs.h>
#include <sys/file.h>

#include "strv.h"
#include "util.h"
#include "path-util.h"
#include "namespace.h"
#include "missing.h"
#include "execute.h"
#include "loopback-setup.h"
#include "mkdir.h"
#include "dev-setup.h"
#include "def.h"

typedef enum MountMode {
        /* This is ordered by priority! */
        INACCESSIBLE,
        READONLY,
        PRIVATE_TMP,
        PRIVATE_VAR_TMP,
        PRIVATE_DEV,
        READWRITE
} MountMode;

typedef struct BindMount {
        const char *path;
        MountMode mode;
        bool done;
        bool ignore;
} BindMount;

static int append_mounts(BindMount **p, char **strv, MountMode mode) {
        char **i;

        assert(p);

        STRV_FOREACH(i, strv) {

                (*p)->ignore = false;

                if ((mode == INACCESSIBLE || mode == READONLY) && (*i)[0] == '-') {
                        (*p)->ignore = true;
                        (*i)++;
                }

                if (!path_is_absolute(*i))
                        return -EINVAL;

                (*p)->path = *i;
                (*p)->mode = mode;
                (*p)++;
        }

        return 0;
}

static int mount_path_compare(const void *a, const void *b) {
        const BindMount *p = a, *q = b;

        if (path_equal(p->path, q->path)) {

                /* If the paths are equal, check the mode */
                if (p->mode < q->mode)
                        return -1;

                if (p->mode > q->mode)
                        return 1;

                return 0;
        }

        /* If the paths are not equal, then order prefixes first */
        if (path_startswith(p->path, q->path))
                return 1;

        if (path_startswith(q->path, p->path))
                return -1;

        return 0;
}

static void drop_duplicates(BindMount *m, unsigned *n) {
        BindMount *f, *t, *previous;

        assert(m);
        assert(n);

        for (f = m, t = m, previous = NULL; f < m+*n; f++) {

                /* The first one wins */
                if (previous && path_equal(f->path, previous->path))
                        continue;

                t->path = f->path;
                t->mode = f->mode;

                previous = t;

                t++;
        }

        *n = t - m;
}

static int mount_dev(BindMount *m) {
        static const char devnodes[] =
                "/dev/null\0"
                "/dev/zero\0"
                "/dev/full\0"
                "/dev/random\0"
                "/dev/urandom\0"
                "/dev/tty\0";

        struct stat devnodes_stat[6] = {};
        const char *d;
        unsigned n = 0;
        _cleanup_umask_ mode_t u;
        int r;

        assert(m);

        u = umask(0000);

        /* First: record device mode_t and dev_t */
        NULSTR_FOREACH(d, devnodes) {
                r = stat(d, &devnodes_stat[n]);
                if (r < 0) {
                        if (errno != ENOENT)
                                return -errno;
                } else {
                        if (!S_ISBLK(devnodes_stat[n].st_mode) &&
                            !S_ISCHR(devnodes_stat[n].st_mode))
                                return -EINVAL;
                }

                n++;
        }

        assert(n == ELEMENTSOF(devnodes_stat));

        r = mount("tmpfs", "/dev", "tmpfs", MS_NOSUID|MS_STRICTATIME, "mode=755");
        if (r < 0)
                return m->ignore ? 0 : -errno;


        mkdir_p("/dev/pts", 0755);

        r = mount("devpts", "/dev/pts", "devpts", MS_NOSUID|MS_NOEXEC, "newinstance,ptmxmode=0666,mode=620,gid=" STRINGIFY(TTY_GID));
        if (r < 0)
                return m->ignore ? 0 : -errno;

        mkdir_p("/dev/shm", 0755);

        r = mount("tmpfs", "/dev/shm", "tmpfs", MS_NOSUID|MS_NODEV|MS_STRICTATIME, "mode=1777");
        if (r < 0)
                return m->ignore ? 0 : -errno;

        /* Second: actually create it */
        n = 0;
        NULSTR_FOREACH(d, devnodes) {
                if (devnodes_stat[n].st_rdev == 0)
                        continue;

                r = mknod(d, devnodes_stat[n].st_mode, devnodes_stat[n].st_rdev);
                if (r < 0)
                        return m->ignore ? 0 : -errno;

                n++;
        }

        dev_setup(NULL);

        return 0;
}

static int apply_mount(
                BindMount *m,
                const char *tmp_dir,
                const char *var_tmp_dir) {

        const char *what;
        int r;

        assert(m);

        switch (m->mode) {

        case PRIVATE_DEV:
                return mount_dev(m);

        case INACCESSIBLE:
                what = "/run/systemd/inaccessible";
                break;

        case READONLY:
        case READWRITE:
                what = m->path;
                break;

        case PRIVATE_TMP:
                what = tmp_dir;
                break;

        case PRIVATE_VAR_TMP:
                what = var_tmp_dir;
                break;

        default:
                assert_not_reached("Unknown mode");
        }

        assert(what);

        r = mount(what, m->path, NULL, MS_BIND|MS_REC, NULL);
        if (r >= 0)
                log_debug("Successfully mounted %s to %s", what, m->path);
        else if (m->ignore && errno == ENOENT)
                r = 0;

        return r;
}

static int make_read_only(BindMount *m) {
        int r;

        assert(m);

        if (m->mode != INACCESSIBLE && m->mode != READONLY)
                return 0;

        r = mount(NULL, m->path, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC, NULL);
        if (r < 0 && !(m->ignore && errno == ENOENT))
                return -errno;

        return 0;
}

int setup_namespace(
                char** read_write_dirs,
                char** read_only_dirs,
                char** inaccessible_dirs,
                char* tmp_dir,
                char* var_tmp_dir,
                bool private_dev,
                unsigned mount_flags) {

        BindMount *m, *mounts = NULL;
        unsigned n;
        int r = 0;

        if (mount_flags == 0)
                mount_flags = MS_SHARED;

        if (unshare(CLONE_NEWNS) < 0)
                return -errno;

        n = !!tmp_dir + !!var_tmp_dir +
                strv_length(read_write_dirs) +
                strv_length(read_only_dirs) +
                strv_length(inaccessible_dirs) +
                private_dev;

        if (n > 0) {
                m = mounts = (BindMount *) alloca(n * sizeof(BindMount));
                r = append_mounts(&m, read_write_dirs, READWRITE);
                if (r < 0)
                        return r;

                r = append_mounts(&m, read_only_dirs, READONLY);
                if (r < 0)
                        return r;

                r = append_mounts(&m, inaccessible_dirs, INACCESSIBLE);
                if (r < 0)
                        return r;

                if (tmp_dir) {
                        m->path = "/tmp";
                        m->mode = PRIVATE_TMP;
                        m++;
                }

                if (var_tmp_dir) {
                        m->path = "/var/tmp";
                        m->mode = PRIVATE_VAR_TMP;
                        m++;
                }

                if (private_dev) {
                        m->path = "/dev";
                        m->mode = PRIVATE_DEV;
                        m++;
                }

                assert(mounts + n == m);

                qsort(mounts, n, sizeof(BindMount), mount_path_compare);
                drop_duplicates(mounts, &n);
        }

        /* Remount / as SLAVE so that nothing now mounted in the namespace
           shows up in the parent */
        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0)
                return -errno;

        for (m = mounts; m < mounts + n; ++m) {
                r = apply_mount(m, tmp_dir, var_tmp_dir);
                if (r < 0)
                        goto fail;
        }

        for (m = mounts; m < mounts + n; ++m) {
                r = make_read_only(m);
                if (r < 0)
                        goto fail;
        }

        /* Remount / as the desired mode */
        if (mount(NULL, "/", NULL, mount_flags | MS_REC, NULL) < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

fail:
        for (m = mounts; m < mounts + n; ++m)
                if (m->done)
                        umount2(m->path, MNT_DETACH);

        return r;
}

static int setup_one_tmp_dir(const char *id, const char *prefix, char **path) {
        _cleanup_free_ char *x = NULL;
        char bid[SD_ID128_STRING_MAX];
        sd_id128_t boot_id;
        int r;

        assert(id);
        assert(prefix);
        assert(path);

        /* We include the boot id in the directory so that after a
         * reboot we can easily identify obsolete directories. */

        r = sd_id128_get_boot(&boot_id);
        if (r < 0)
                return r;

        x = strjoin(prefix, "/systemd-private-", sd_id128_to_string(boot_id, bid), "-", id, "-XXXXXX", NULL);
        if (!x)
                return -ENOMEM;

        RUN_WITH_UMASK(0077)
                if (!mkdtemp(x))
                        return -errno;

        RUN_WITH_UMASK(0000) {
                char *y;

                y = strappenda(x, "/tmp");

                if (mkdir(y, 0777 | S_ISVTX) < 0)
                        return -errno;
        }

        *path = x;
        x = NULL;

        return 0;
}

int setup_tmp_dirs(const char *id, char **tmp_dir, char **var_tmp_dir) {
        char *a, *b;
        int r;

        assert(id);
        assert(tmp_dir);
        assert(var_tmp_dir);

        r = setup_one_tmp_dir(id, "/tmp", &a);
        if (r < 0)
                return r;

        r = setup_one_tmp_dir(id, "/var/tmp", &b);
        if (r < 0) {
                char *t;

                t = strappenda(a, "/tmp");
                rmdir(t);
                rmdir(a);

                free(a);
                return r;
        }

        *tmp_dir = a;
        *var_tmp_dir = b;

        return 0;
}

int setup_netns(int netns_storage_socket[2]) {
        _cleanup_close_ int netns = -1;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        int r;

        assert(netns_storage_socket);
        assert(netns_storage_socket[0] >= 0);
        assert(netns_storage_socket[1] >= 0);

        /* We use the passed socketpair as a storage buffer for our
         * namespace reference fd. Whatever process runs this first
         * shall create a new namespace, all others should just join
         * it. To serialize that we use a file lock on the socket
         * pair.
         *
         * It's a bit crazy, but hey, works great! */

        if (lockf(netns_storage_socket[0], F_LOCK, 0) < 0)
                return -errno;

        if (recvmsg(netns_storage_socket[0], &mh, MSG_DONTWAIT|MSG_CMSG_CLOEXEC) < 0) {
                if (errno != EAGAIN) {
                        r = -errno;
                        goto fail;
                }

                /* Nothing stored yet, so let's create a new namespace */

                if (unshare(CLONE_NEWNET) < 0) {
                        r = -errno;
                        goto fail;
                }

                loopback_setup();

                netns = open("/proc/self/ns/net", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (netns < 0) {
                        r = -errno;
                        goto fail;
                }

                r = 1;
        } else {
                /* Yay, found something, so let's join the namespace */

                for (cmsg = CMSG_FIRSTHDR(&mh); cmsg; cmsg = CMSG_NXTHDR(&mh, cmsg)) {
                        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                                assert(cmsg->cmsg_len == CMSG_LEN(sizeof(int)));
                                netns = *(int*) CMSG_DATA(cmsg);
                        }
                }

                if (setns(netns, CLONE_NEWNET) < 0) {
                        r = -errno;
                        goto fail;
                }

                r = 0;
        }

        cmsg = CMSG_FIRSTHDR(&mh);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &netns, sizeof(int));
        mh.msg_controllen = cmsg->cmsg_len;

        if (sendmsg(netns_storage_socket[1], &mh, MSG_DONTWAIT|MSG_NOSIGNAL) < 0) {
                r = -errno;
                goto fail;
        }

fail:
        lockf(netns_storage_socket[0], F_ULOCK, 0);

        return r;
}
