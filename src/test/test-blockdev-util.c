/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/file.h>

#include "blockdev-util.h"
#include "errno-util.h"
#include "tests.h"
#include "fd-util.h"

static void test_path_is_encrypted_one(const char *p, int expect) {
        int r;

        r = path_is_encrypted(p);
        if (r == -ENOENT || (r < 0 && ERRNO_IS_PRIVILEGE(r)))
                /* This might fail, if btrfs is used and we run in a container. In that case we cannot
                 * resolve the device node paths that BTRFS_IOC_DEV_INFO returns, because the device nodes
                 * are unlikely to exist in the container. But if we can't stat() them we cannot determine
                 * the dev_t of them, and thus cannot figure out if they are enrypted. Hence let's just
                 * ignore ENOENT here. Also skip the test if we lack privileges. */
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

TEST(lock_whole_disk_from_devname) {
        if(access("/dev/sda1", F_OK) == 0){
                _cleanup_close_ int fd;

                log_info("/* %s (lock_whole_disk /dev/sda1) */", __func__);

                fd = lock_whole_disk_from_devname("/dev/sda1", O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY ,LOCK_EX|LOCK_NB);

                log_info("get BSD lock fd: %d", fd);

                assert_se(fd > 0);
        }
}

DEFINE_TEST_MAIN(LOG_INFO);
