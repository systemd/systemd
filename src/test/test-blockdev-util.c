/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "blockdev-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "path-util.h"
#include "tests.h"

#define _cleanup_fp_ __attribute__((cleanup(cleanup_file)))

int set_permissions(char *devpath);
char *get_device_path(void);

static void cleanup_file(FILE **fp) {
    if (fp && *fp) {
        fclose(*fp);
        *fp = NULL;
    }
}

static void test_path_is_encrypted_one(const char *p, int expect) {
        int r;

        r = path_is_encrypted(p);
        if (IN_SET(r, -ENOENT, -ELOOP) || ERRNO_IS_NEG_PRIVILEGE(r))
                /* This might fail, if btrfs is used and we run in a container. In that case we cannot
                 * resolve the device node paths that BTRFS_IOC_DEV_INFO returns, because the device nodes
                 * are unlikely to exist in the container. But if we can't stat() them we cannot determine
                 * the dev_t of them, and thus cannot figure out if they are encrypted. Hence let's just
                 * ignore ENOENT here. Also skip the test if we lack privileges.
                 * ELOOP might happen if the mount point is a symlink, as seen with under
                 * some rpm-ostree distros */
                return;
        assert_se(r >= 0);

        log_info("%s encrypted: %s", p, yes_no(r));

        assert_se(expect < 0 || ((r > 0) == (expect > 0)));
}

TEST(get_block_device) {
        _cleanup_(sd_device_unrefp) sd_device *sd_dev = NULL;
        _cleanup_free_ char *dev_path = NULL;
        _cleanup_close_ int fd =  -EBADF;
        int r;
        dev_t devnum;
        struct stat st;

        dev_path = get_device_path();
        ASSERT_OK(dev_path != NULL);
        ASSERT_OK(set_permissions(dev_path) == 0);

        fd = open(dev_path, O_RDWR);
        ASSERT_OK(fd);

        r = block_device_new_from_fd(fd, 0, &sd_dev);
        ASSERT_OK(r);

        /* r = get_block_device(dev_path, &devnum);
         * ASSERT_OK(r); */

        ASSERT_OK(stat(dev_path, &st) == 0);
        ASSERT_OK(S_ISBLK(st.st_mode));
        devnum = (unsigned long) st.st_rdev;

        r = sd_device_new_from_devnum(&sd_dev, 'b', devnum);
        ASSERT_OK(r);

        r = device_is_devtype(sd_dev, "disk");
        ASSERT_OK(r);

        sd_device *parent = NULL;
        r = sd_device_get_parent(sd_dev, &parent);
        ASSERT_OK(r);
}

TEST(path_is_encrypted) {
        int booted = sd_booted(); /* If this is run in build environments such as koji, /dev/ might be a
                                   * regular fs. Don't assume too much if not running under systemd. */

        log_info("/* %s (sd_booted=%d) */", __func__, booted);

        test_path_is_encrypted_one("/home", -1);
        test_path_is_encrypted_one("/var", -1);
        test_path_is_encrypted_one("/", -1);
        test_path_is_encrypted_one("/proc", false);
        test_path_is_encrypted_one("/sys", false);
        test_path_is_encrypted_one("/dev", booted > 0 ? false : -1);
}

TEST(partscan_enabled) {

        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_allow_uninitialized(e) >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, "block", /* match = */ true) >= 0);

        FOREACH_DEVICE(e, dev) {
                _cleanup_close_ int fd = -EBADF;
                const char *name;

                r = sd_device_get_devname(dev, &name);
                if (r < 0) {
                        log_warning_errno(r, "Found block device without a name, skipping.");
                        continue;
                }

                fd = sd_device_open(dev, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
                if (fd < 0) {
                        log_warning_errno(fd, "Found block device '%s' which we cannot open, skipping: %m", name);
                        continue;
                }

                r = blockdev_partscan_enabled_fd(fd);
                if (r < 0) {
                        log_warning_errno(r, "Failed to determine if block device '%s' has partition"    \
                                             " scanning enabled, skipping: %m", name);
                        continue;
                }
                log_info("%s has partition scanning enabled: %s", name, yes_no(r));
        }
}

int set_permissions(char *devpath) {
        struct stat fs;
        int r;

        /* fs.st_mode initialized */
        r = stat(devpath, &fs);
        if (r ==- 1)
                return -1;

        /* Set group and other write permissions */
        r = chmod(devpath, (fs.st_mode) | (S_IWGRP+S_IWOTH));
        if (r != 0)
                return -1;

        stat(devpath, &fs);
        if (r ==- 1)
                return -1;

        return(0);
}

char *get_device_path(void) {
        char line[256];
        char *device_path = NULL;

        _cleanup_fp_ FILE *file_path = fopen("/proc/partitions", "r");
        ASSERT_OK(file_path != NULL);

        fgets(line, sizeof(line), file_path);
        while (fgets(line, sizeof(line), file_path)) {
                int major, minor;
                unsigned long blocks;
                char name[128];

                if (sscanf(line, " %d %d %lu %127s", &major, &minor, &blocks, name) == 4) {
                        device_path = path_join("/dev", name);
                        char *dev_name = basename((char *)device_path);
                        if (strcmp(name, dev_name) == 0)
                                log_info("%s is a partitioned device or contains partitions.\n", device_path);
                        else
                                log_info("%s is not a partition or does not contain partitions.\n", device_path);
                }
        }

        return device_path;
}

DEFINE_TEST_MAIN(LOG_DEBUG);
