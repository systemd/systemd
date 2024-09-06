/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "blockdev-util.h"
#include "device-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "tests.h"

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
                        log_warning_errno(r, "Failed to determine if block device '%s' has partition scanning enabled, skipping: %m", name);
                        continue;
                }

                log_info("%s has partition scanning enabled: %s", name, yes_no(r));
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
