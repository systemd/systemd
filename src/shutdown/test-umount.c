/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "detach-swap.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "path-util.h"
#include "string-util.h"
#include "tests.h"
#include "umount.h"

static void test_mount_points_list_one(const char *fname) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, mp_list_head);
        _cleanup_fclose_ FILE *f = NULL;

        log_info("/* %s(\"%s\") */", __func__, fname ?: "/proc/self/mountinfo");

        if (fname) {
                _cleanup_free_ char *testdata_fname = NULL;
                assert_se(get_testdata_dir(fname, &testdata_fname) >= 0);
                ASSERT_NOT_NULL(f = fopen(testdata_fname, "re"));
        }

        LIST_HEAD_INIT(mp_list_head);
        assert_se(mount_points_list_get(f, &mp_list_head) >= 0);

        LIST_FOREACH(mount_point, m, mp_list_head)
                log_debug("path=%s o=%s f=0x%lx try-ro=%s",
                          m->path,
                          strempty(m->remount_options),
                          m->remount_flags,
                          yes_no(m->try_remount_ro));
}

TEST(mount_points_list) {
        test_mount_points_list_one(NULL);
        test_mount_points_list_one("/test-umount/empty.mountinfo");
        test_mount_points_list_one("/test-umount/garbled.mountinfo");
        test_mount_points_list_one("/test-umount/rhbug-1554943.mountinfo");
}

static void test_swap_list_one(const char *fname) {
        _cleanup_(swap_devices_list_free) LIST_HEAD(SwapDevice, sd_list_head);
        _cleanup_free_ char *testdata_fname = NULL;
        int r;

        log_info("/* %s(\"%s\") */", __func__, fname ?: "/proc/swaps");

        if (fname) {
                assert_se(get_testdata_dir(fname, &testdata_fname) >= 0);
                fname = testdata_fname;
        }

        LIST_HEAD_INIT(sd_list_head);
        r = swap_list_get(fname, &sd_list_head);
        if (ERRNO_IS_PRIVILEGE(r))
                return;
        assert_se(r >= 0);

        LIST_FOREACH(swap_device, m, sd_list_head)
                log_debug("path=%s", m->path);
}

TEST(swap_list) {
        test_swap_list_one(NULL);
        test_swap_list_one("/test-umount/example.swaps");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
