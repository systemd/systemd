/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "errno-util.h"
#include "log.h"
#include "path-util.h"
#include "string-util.h"
#include "tests.h"
#include "umount.h"
#include "util.h"

static void test_mount_points_list_one(const char *fname) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, mp_list_head);
        _cleanup_free_ char *testdata_fname = NULL;

        log_info("/* %s(\"%s\") */", __func__, fname ?: "/proc/self/mountinfo");

        if (fname) {
                assert_se(get_testdata_dir(fname, &testdata_fname) >= 0);
                fname = testdata_fname;
        }

        LIST_HEAD_INIT(mp_list_head);
        assert_se(mount_points_list_get(fname, &mp_list_head) >= 0);

        LIST_FOREACH(mount_point, m, mp_list_head)
                log_debug("path=%s o=%s f=0x%lx try-ro=%s dev=%u:%u",
                          m->path,
                          strempty(m->remount_options),
                          m->remount_flags,
                          yes_no(m->try_remount_ro),
                          major(m->devnum), minor(m->devnum));
}

TEST(mount_points_list) {
        test_mount_points_list_one(NULL);
        test_mount_points_list_one("/test-umount/empty.mountinfo");
        test_mount_points_list_one("/test-umount/garbled.mountinfo");
        test_mount_points_list_one("/test-umount/rhbug-1554943.mountinfo");
}

static void test_swap_list_one(const char *fname) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, mp_list_head);
        _cleanup_free_ char *testdata_fname = NULL;
        int r;

        log_info("/* %s(\"%s\") */", __func__, fname ?: "/proc/swaps");

        if (fname) {
                assert_se(get_testdata_dir(fname, &testdata_fname) >= 0);
                fname = testdata_fname;
        }

        LIST_HEAD_INIT(mp_list_head);
        r = swap_list_get(fname, &mp_list_head);
        if (ERRNO_IS_PRIVILEGE(r))
                return;
        assert_se(r >= 0);

        LIST_FOREACH(mount_point, m, mp_list_head)
                log_debug("path=%s o=%s f=0x%lx try-ro=%s dev=%u:%u",
                          m->path,
                          strempty(m->remount_options),
                          m->remount_flags,
                          yes_no(m->try_remount_ro),
                          major(m->devnum), minor(m->devnum));
}

TEST(swap_list) {
        test_swap_list_one(NULL);
        test_swap_list_one("/test-umount/example.swaps");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
