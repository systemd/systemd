/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "devnum-util.h"
#include "directory-policy.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

/* The metadata directory systemd-sysext places in the top-level directory of a merged /usr/ */
#define SYSEXT_DOT_DIRECTORY ".systemd-sysext"

static const char* const directory_policy_table[_DIRECTORY_POLICY_MAX] = {
        [DIRECTORY_POLICY_NO]   = "no",
        [DIRECTORY_POLICY_YES]  = "yes",
        [DIRECTORY_POLICY_AUTO] = "auto",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(directory_policy, DirectoryPolicy, DIRECTORY_POLICY_YES);

static int fd_get_file_system_devnum(int fd, dev_t *ret) {
        struct stat st;
        int r;

        assert(fd >= 0);
        assert(ret);

        /* Returns a dev_t identifying the file system the specified fd is located on. Note that btrfs
         * assigns a separate anonymous st_dev to each subvolume, hence look for the backing block device
         * first, and only fall back to st_dev for file systems without one (tmpfs, overlayfs, btrfs RAID,
         * …), or if the block device cannot be determined. */

        r = get_block_device_fd(fd, ret);
        if (r > 0)
                return 0;
        if (r < 0)
                log_debug_errno(r, "Failed to determine backing block device of file system, using st_dev instead: %m");

        if (fstat(fd, &st) < 0)
                return -errno;

        *ret = st.st_dev;
        return 0;
}

int directory_policy_check_auto(
                const char *path,
                int fd,
                const dev_t *trusted_devnums) {

        dev_t devnum;
        int r;

        assert(fd >= 0);

        /* Checks whether the directory referenced by the specified fd is acceptable as directory image under
         * the "auto" policy (the "yes" and "no" policies need no check). Returns > 0 if so, 0 if not,
         * negative errno on error. A directory is only acceptable if it is located below /usr/ or /var/, on
         * tmpfs, on dm-crypt or dm-verity storage, or on one of the specified trusted file systems (which
         * are identified by the dev_t fd_get_file_system_devnum() returns for them, as array terminated by
         * a zero dev_t, may be NULL). tmpfs is trusted since its contents only exist at runtime and hence
         * can only have been placed there by the running system itself, they cannot be manipulated offline
         * like the contents of unprotected persistent storage (e.g. the ESP) can.
         *
         * The path should be the absolute path of the directory relative to the root directory of the OS
         * tree we operate on, i.e. with any --root= prefix removed. It may be NULL, in which case the
         * /usr/ + /var/ prefix check is skipped. */

        if (path && PATH_STARTSWITH_SET(path, "/usr", "/var")) {
                log_debug("Directory '%s' is located below /usr/ or /var/, permitting.", path);
                return true;
        }

        r = fd_is_fs_type(fd, TMPFS_MAGIC);
        if (r < 0)
                log_debug_errno(r, "Failed to determine whether directory '%s' is located on tmpfs, assuming not: %m", strna(path));
        else if (r > 0) {
                log_debug("Directory '%s' is located on tmpfs, permitting.", strna(path));
                return true;
        }

        r = fd_is_encrypted(fd, BLOCK_DEVICE_ENCRYPTED_DM_CRYPT|BLOCK_DEVICE_ENCRYPTED_DM_VERITY);
        if (r < 0)
                log_debug_errno(r, "Failed to determine whether directory '%s' is backed by dm-crypt/dm-verity storage, assuming not: %m", strna(path));
        else if (r > 0) {
                log_debug("Directory '%s' is backed by dm-crypt/dm-verity storage, permitting.", strna(path));
                return true;
        }

        r = fd_get_file_system_devnum(fd, &devnum);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine file system of directory '%s': %m", strna(path));

        for (const dev_t *d = trusted_devnums; d && *d != 0; d++)
                if (*d == devnum) {
                        log_debug("Directory '%s' is located on trusted file system " DEVNUM_FORMAT_STR ", permitting.", strna(path), DEVNUM_FORMAT_VAL(devnum));
                        return true;
                }

        log_debug("Directory '%s' is neither located below /usr/ or /var/, nor on tmpfs, nor backed by dm-crypt/dm-verity storage, nor located on a trusted file system, refusing.", strna(path));
        return false;
}

static void trusted_file_systems_add(dev_t trusted[static TRUSTED_FILE_SYSTEMS_MAX], dev_t devnum) {
        size_t n = 0;

        assert(trusted);

        /* Appends the specified dev_t to the zero-terminated array, unless it is already in it */

        if (devnum == 0)
                return;

        for (; trusted[n] != 0; n++)
                if (trusted[n] == devnum)
                        return;

        assert(n + 1 < TRUSTED_FILE_SYSTEMS_MAX);
        trusted[n] = devnum;
        trusted[n + 1] = 0;
}

static void add_trusted_file_system(int fd, const char *path, dev_t trusted[static TRUSTED_FILE_SYSTEMS_MAX]) {
        dev_t devnum;
        int r;

        assert(fd >= 0);
        assert(path);
        assert(trusted);

        r = fd_get_file_system_devnum(fd, &devnum);
        if (r < 0) {
                log_warning_errno(r, "Failed to determine file system of '%s', ignoring: %m", path);
                return;
        }

        trusted_file_systems_add(trusted, devnum);
}

static int add_trusted_sysext_backing(int fd, const char *path, dev_t trusted[static TRUSTED_FILE_SYSTEMS_MAX]) {
        _cleanup_free_ char *dev_path = NULL, *dev_str = NULL, *backing_path = NULL, *backing_str = NULL;
        struct stat st;
        dev_t devnum;
        int r;

        assert(fd >= 0);
        assert(path);
        assert(trusted);

        /* If /usr/ is currently covered by a sysext overlayfs (i.e. on refresh), the st_dev of /usr/ is the
         * one of the overlayfs, not of the actual /usr/ file system. In that case, the "backing" file in the
         * .systemd-sysext/ metadata directory tells us the backing file system. We only trust it if the "dev"
         * file next to it matches the st_dev of the directory, i.e. if we are looking at a live overlayfs we
         * set up, and not at a copy of one. Returns negative errno only on OOM, all other errors are logged and
         * ignored. */

        dev_path = path_join(SYSEXT_DOT_DIRECTORY, "dev");
        if (!dev_path)
                return log_oom();

        r = read_one_line_file_at(fd, dev_path, &dev_str);
        if (r == -ENOENT)
                return 0;
        if (r < 0) {
                log_warning_errno(r, "Failed to read '%s/%s', ignoring: %m", path, dev_path);
                return 0;
        }

        r = parse_devnum(dev_str, &devnum);
        if (r < 0) {
                log_warning_errno(r, "Failed to parse '%s/%s', ignoring: %m", path, dev_path);
                return 0;
        }

        if (fstat(fd, &st) < 0) {
                log_warning_errno(errno, "Failed to stat '%s', ignoring: %m", path);
                return 0;
        }

        if (st.st_dev != devnum) {
                log_debug("'%s/%s' does not match the file system of '%s', ignoring.", path, dev_path, path);
                return 0;
        }

        backing_path = path_join(SYSEXT_DOT_DIRECTORY, "backing");
        if (!backing_path)
                return log_oom();

        r = read_one_line_file_at(fd, backing_path, &backing_str);
        if (r == -ENOENT)
                return 0;
        if (r < 0) {
                log_warning_errno(r, "Failed to read '%s/%s', ignoring: %m", path, backing_path);
                return 0;
        }

        r = parse_devnum(backing_str, &devnum);
        if (r < 0) {
                log_warning_errno(r, "Failed to parse '%s/%s', ignoring: %m", path, backing_path);
                return 0;
        }

        log_debug("'%s' is covered by an overlayfs, backed by file system " DEVNUM_FORMAT_STR ".", path, DEVNUM_FORMAT_VAL(devnum));
        trusted_file_systems_add(trusted, devnum);
        return 0;
}

int acquire_trusted_file_systems(const char *root, dev_t ret[static TRUSTED_FILE_SYSTEMS_MAX]) {
        int r;

        assert(ret);

        /* Determines the file systems backing /, /usr/ and /var/ of the OS tree we operate on. Fills in the
         * array, terminated by a zero dev_t. */

        ret[0] = 0;

        FOREACH_STRING(p, "/", "/usr", "/var") {
                _cleanup_free_ char *j = NULL;
                _cleanup_close_ int fd = -EBADF;

                /* We do not allow these to be symlinks, hence do not resolve them */
                j = path_join(strempty(root), p);
                if (!j)
                        return log_oom();

                fd = xopenat(AT_FDCWD, j, O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
                if (fd < 0) {
                        log_full_errno(fd == -ENOENT ? LOG_DEBUG : LOG_WARNING, fd,
                                       "Failed to open '%s', ignoring: %m", j);
                        continue;
                }

                add_trusted_file_system(fd, j, ret);

                if (streq(p, "/usr")) {
                        r = add_trusted_sysext_backing(fd, j, ret);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}
