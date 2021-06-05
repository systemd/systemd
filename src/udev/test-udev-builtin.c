/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "udev-builtin.h"

static void test_udev_builtin_cmd_to_ptr(void) {
        log_info("/* %s */", __func__);

        /* Those could have been static asserts, but ({}) is not allowed there. */
#if HAVE_BLKID
        assert_se(UDEV_BUILTIN_CMD_TO_PTR(UDEV_BUILTIN_BLKID));
        assert_se(PTR_TO_UDEV_BUILTIN_CMD(UDEV_BUILTIN_CMD_TO_PTR(UDEV_BUILTIN_BLKID)) == UDEV_BUILTIN_BLKID);
#endif
        assert_se(UDEV_BUILTIN_CMD_TO_PTR(UDEV_BUILTIN_BTRFS));
        assert_se(PTR_TO_UDEV_BUILTIN_CMD(UDEV_BUILTIN_CMD_TO_PTR(UDEV_BUILTIN_BTRFS)) == UDEV_BUILTIN_BTRFS);
        assert_se(PTR_TO_UDEV_BUILTIN_CMD(UDEV_BUILTIN_CMD_TO_PTR(_UDEV_BUILTIN_INVALID)) == _UDEV_BUILTIN_INVALID);

        assert_se(PTR_TO_UDEV_BUILTIN_CMD(NULL) == _UDEV_BUILTIN_INVALID);
        assert_se(PTR_TO_UDEV_BUILTIN_CMD((void*) 10000) == _UDEV_BUILTIN_INVALID);
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_udev_builtin_cmd_to_ptr();
}
