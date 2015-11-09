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

#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>

#include "alloc-util.h"
#include "btrfs-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "lockfile-util.h"
#include "machine-pool.h"
#include "mkdir.h"
#include "mount-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "util.h"

#define VAR_LIB_MACHINES_SIZE_START (1024UL*1024UL*500UL)
#define VAR_LIB_MACHINES_FREE_MIN (1024UL*1024UL*750UL)

static int check_btrfs(void) {
        struct statfs sfs;

        if (statfs("/var/lib/machines", &sfs) < 0) {
                if (errno != ENOENT)
                        return -errno;

                if (statfs("/var/lib", &sfs) < 0)
                        return -errno;
        }

        return F_TYPE_EQUAL(sfs.f_type, BTRFS_SUPER_MAGIC);
}

static int setup_machine_raw(uint64_t size, sd_bus_error *error) {
        _cleanup_free_ char *tmp = NULL;
        _cleanup_close_ int fd = -1;
        struct statvfs ss;
        pid_t pid = 0;
        siginfo_t si;
        int r;

        /* We want to be able to make use of btrfs-specific file
         * system features, in particular subvolumes, reflinks and
         * quota. Hence, if we detect that /var/lib/machines.raw is
         * not located on btrfs, let's create a loopback file, place a
         * btrfs file system into it, and mount it to
         * /var/lib/machines. */

        fd = open("/var/lib/machines.raw", O_RDWR|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd >= 0) {
                r = fd;
                fd = -1;
                return r;
        }

        if (errno != ENOENT)
                return sd_bus_error_set_errnof(error, errno, "Failed to open /var/lib/machines.raw: %m");

        r = tempfn_xxxxxx("/var/lib/machines.raw", NULL, &tmp);
        if (r < 0)
                return r;

        (void) mkdir_p_label("/var/lib", 0755);
        fd = open(tmp, O_RDWR|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0600);
        if (fd < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to create /var/lib/machines.raw: %m");

        if (fstatvfs(fd, &ss) < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to determine free space on /var/lib/machines.raw: %m");
                goto fail;
        }

        if (ss.f_bsize * ss.f_bavail < VAR_LIB_MACHINES_FREE_MIN) {
                r = sd_bus_error_setf(error, SD_BUS_ERROR_FAILED, "Not enough free disk space to set up /var/lib/machines.");
                goto fail;
        }

        if (ftruncate(fd, size) < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to enlarge /var/lib/machines.raw: %m");
                goto fail;
        }

        pid = fork();
        if (pid < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to fork mkfs.btrfs: %m");
                goto fail;
        }

        if (pid == 0) {

                /* Child */

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();
                assert_se(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0);

                fd = safe_close(fd);

                execlp("mkfs.btrfs", "-Lvar-lib-machines", tmp, NULL);
                if (errno == ENOENT)
                        return 99;

                _exit(EXIT_FAILURE);
        }

        r = wait_for_terminate(pid, &si);
        if (r < 0) {
                sd_bus_error_set_errnof(error, r, "Failed to wait for mkfs.btrfs: %m");
                goto fail;
        }

        pid = 0;

        if (si.si_code != CLD_EXITED) {
                r = sd_bus_error_setf(error, SD_BUS_ERROR_FAILED, "mkfs.btrfs died abnormally.");
                goto fail;
        }
        if (si.si_status == 99) {
                r = sd_bus_error_set_errnof(error, ENOENT, "Cannot set up /var/lib/machines, mkfs.btrfs is missing");
                goto fail;
        }
        if (si.si_status != 0) {
                r = sd_bus_error_setf(error, SD_BUS_ERROR_FAILED, "mkfs.btrfs failed with error code %i", si.si_status);
                goto fail;
        }

        r = rename_noreplace(AT_FDCWD, tmp, AT_FDCWD, "/var/lib/machines.raw");
        if (r < 0) {
                sd_bus_error_set_errnof(error, r, "Failed to move /var/lib/machines.raw into place: %m");
                goto fail;
        }

        r = fd;
        fd = -1;

        return r;

fail:
        unlink_noerrno(tmp);

        if (pid > 1)
                kill_and_sigcont(pid, SIGKILL);

        return r;
}

int setup_machine_directory(uint64_t size, sd_bus_error *error) {
        _cleanup_release_lock_file_ LockFile lock_file = LOCK_FILE_INIT;
        struct loop_info64 info = {
                .lo_flags = LO_FLAGS_AUTOCLEAR,
        };
        _cleanup_close_ int fd = -1, control = -1, loop = -1;
        _cleanup_free_ char* loopdev = NULL;
        char tmpdir[] = "/tmp/machine-pool.XXXXXX", *mntdir = NULL;
        bool tmpdir_made = false, mntdir_made = false, mntdir_mounted = false;
        char buf[FORMAT_BYTES_MAX];
        int r, nr = -1;

        /* btrfs cannot handle file systems < 16M, hence use this as minimum */
        if (size == (uint64_t) -1)
                size = VAR_LIB_MACHINES_SIZE_START;
        else if (size < 16*1024*1024)
                size = 16*1024*1024;

        /* Make sure we only set the directory up once at a time */
        r = make_lock_file("/run/systemd/machines.lock", LOCK_EX, &lock_file);
        if (r < 0)
                return r;

        r = check_btrfs();
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to determine whether /var/lib/machines is located on btrfs: %m");
        if (r > 0) {
                (void) btrfs_subvol_make_label("/var/lib/machines");

                r = btrfs_quota_enable("/var/lib/machines", true);
                if (r < 0)
                        log_warning_errno(r, "Failed to enable quota for /var/lib/machines, ignoring: %m");

                r = btrfs_subvol_auto_qgroup("/var/lib/machines", 0, true);
                if (r < 0)
                        log_warning_errno(r, "Failed to set up default quota hierarchy for /var/lib/machines, ignoring: %m");

                return 1;
        }

        if (path_is_mount_point("/var/lib/machines", AT_SYMLINK_FOLLOW) > 0) {
                log_debug("/var/lib/machines is already a mount point, not creating loopback file for it.");
                return 0;
        }

        r = dir_is_populated("/var/lib/machines");
        if (r < 0 && r != -ENOENT)
                return r;
        if (r > 0) {
                log_debug("/var/log/machines is already populated, not creating loopback file for it.");
                return 0;
        }

        r = mkfs_exists("btrfs");
        if (r == -ENOENT) {
                log_debug("mkfs.btrfs is missing, cannot create loopback file for /var/lib/machines.");
                return 0;
        }
        if (r < 0)
                return r;

        fd = setup_machine_raw(size, error);
        if (fd < 0)
                return fd;

        control = open("/dev/loop-control", O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (control < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to open /dev/loop-control: %m");

        nr = ioctl(control, LOOP_CTL_GET_FREE);
        if (nr < 0)
                return sd_bus_error_set_errnof(error, errno, "Failed to allocate loop device: %m");

        if (asprintf(&loopdev, "/dev/loop%i", nr) < 0) {
                r = -ENOMEM;
                goto fail;
        }

        loop = open(loopdev, O_CLOEXEC|O_RDWR|O_NOCTTY|O_NONBLOCK);
        if (loop < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to open loopback device: %m");
                goto fail;
        }

        if (ioctl(loop, LOOP_SET_FD, fd) < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to bind loopback device: %m");
                goto fail;
        }

        if (ioctl(loop, LOOP_SET_STATUS64, &info) < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to enable auto-clear for loopback device: %m");
                goto fail;
        }

        /* We need to make sure the new /var/lib/machines directory
         * has an access mode of 0700 at the time it is first made
         * available. mkfs will create it with 0755 however. Hence,
         * let's mount the directory into an inaccessible directory
         * below /tmp first, fix the access mode, and move it to the
         * public place then. */

        if (!mkdtemp(tmpdir)) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to create temporary mount parent directory: %m");
                goto fail;
        }
        tmpdir_made = true;

        mntdir = strjoina(tmpdir, "/mnt");
        if (mkdir(mntdir, 0700) < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to create temporary mount directory: %m");
                goto fail;
        }
        mntdir_made = true;

        if (mount(loopdev, mntdir, "btrfs", 0, NULL) < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to mount loopback device: %m");
                goto fail;
        }
        mntdir_mounted = true;

        r = btrfs_quota_enable(mntdir, true);
        if (r < 0)
                log_warning_errno(r, "Failed to enable quota, ignoring: %m");

        r = btrfs_subvol_auto_qgroup(mntdir, 0, true);
        if (r < 0)
                log_warning_errno(r, "Failed to set up default quota hierarchy, ignoring: %m");

        if (chmod(mntdir, 0700) < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to fix owner: %m");
                goto fail;
        }

        (void) mkdir_p_label("/var/lib/machines", 0700);

        if (mount(mntdir, "/var/lib/machines", NULL, MS_BIND, NULL) < 0) {
                r = sd_bus_error_set_errnof(error, errno, "Failed to mount directory into right place: %m");
                goto fail;
        }

        (void) syncfs(fd);

        log_info("Set up /var/lib/machines as btrfs loopback file system of size %s mounted on /var/lib/machines.raw.", format_bytes(buf, sizeof(buf), size));

        (void) umount2(mntdir, MNT_DETACH);
        (void) rmdir(mntdir);
        (void) rmdir(tmpdir);

        return 1;

fail:
        if (mntdir_mounted)
                (void) umount2(mntdir, MNT_DETACH);

        if (mntdir_made)
                (void) rmdir(mntdir);
        if (tmpdir_made)
                (void) rmdir(tmpdir);

        if (loop >= 0) {
                (void) ioctl(loop, LOOP_CLR_FD);
                loop = safe_close(loop);
        }

        if (control >= 0 && nr >= 0)
                (void) ioctl(control, LOOP_CTL_REMOVE, nr);

        return r;
}

static int sync_path(const char *p) {
        _cleanup_close_ int fd = -1;

        fd = open(p, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return -errno;

        if (syncfs(fd) < 0)
                return -errno;

        return 0;
}

int grow_machine_directory(void) {
        char buf[FORMAT_BYTES_MAX];
        struct statvfs a, b;
        uint64_t old_size, new_size, max_add;
        int r;

        /* Ensure the disk space data is accurate */
        sync_path("/var/lib/machines");
        sync_path("/var/lib/machines.raw");

        if (statvfs("/var/lib/machines.raw", &a) < 0)
                return -errno;

        if (statvfs("/var/lib/machines", &b) < 0)
                return -errno;

        /* Don't grow if not enough disk space is available on the host */
        if (((uint64_t) a.f_bavail * (uint64_t) a.f_bsize) <= VAR_LIB_MACHINES_FREE_MIN)
                return 0;

        /* Don't grow if at least 1/3th of the fs is still free */
        if (b.f_bavail > b.f_blocks / 3)
                return 0;

        /* Calculate how much we are willing to add at most */
        max_add = ((uint64_t) a.f_bavail * (uint64_t) a.f_bsize) - VAR_LIB_MACHINES_FREE_MIN;

        /* Calculate the old size */
        old_size = (uint64_t) b.f_blocks * (uint64_t) b.f_bsize;

        /* Calculate the new size as three times the size of what is used right now */
        new_size = ((uint64_t) b.f_blocks - (uint64_t) b.f_bavail) * (uint64_t) b.f_bsize * 3;

        /* Always, grow at least to the start size */
        if (new_size < VAR_LIB_MACHINES_SIZE_START)
                new_size = VAR_LIB_MACHINES_SIZE_START;

        /* If the new size is smaller than the old size, don't grow */
        if (new_size < old_size)
                return 0;

        /* Ensure we never add more than the maximum */
        if (new_size > old_size + max_add)
                new_size = old_size + max_add;

        r = btrfs_resize_loopback("/var/lib/machines", new_size, true);
        if (r <= 0)
                return r;

        /* Also bump the quota, of both the subvolume leaf qgroup, as
         * well as of any subtree quota group by the same id but a
         * higher level, if it exists. */
        (void) btrfs_qgroup_set_limit("/var/lib/machines", 0, new_size);
        (void) btrfs_subvol_set_subtree_quota_limit("/var/lib/machines", 0, new_size);

        log_info("Grew /var/lib/machines btrfs loopback file system to %s.", format_bytes(buf, sizeof(buf), new_size));
        return 1;
}
