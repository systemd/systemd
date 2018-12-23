/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "log.h"
#include "path-util.h"
#include "string-util.h"
#include "tests.h"
#include "umount.h"
#include "util.h"

static void test_mount_points_list(const char *fname) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, mp_list_head);
        _cleanup_free_ char *testdata_fname = NULL;
        MountPoint *m;

        log_info("/* %s(\"%s\") */", __func__, fname ?: "/proc/self/mountinfo");

        if (fname)
                fname = testdata_fname = path_join(get_testdata_dir(), fname);

        LIST_HEAD_INIT(mp_list_head);
        assert_se(mount_points_list_get(fname, &mp_list_head) >= 0);

        LIST_FOREACH(mount_point, m, mp_list_head)
        log_debug("path=%s o=%s f=0x%lx try-ro=%s dev=%u:%u",
                  m->path,
                  strempty(m->remount_options),
                  m->remount_flags,
                  yes_no(m->try_remount_ro),
                  major(m->devnum),
                  minor(m->devnum));
}

static void test_swap_list(const char *fname) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, mp_list_head);
        _cleanup_free_ char *testdata_fname = NULL;
        MountPoint *m;

        log_info("/* %s(\"%s\") */", __func__, fname ?: "/proc/swaps");

        if (fname)
                fname = testdata_fname = path_join(get_testdata_dir(), fname);

        LIST_HEAD_INIT(mp_list_head);
        assert_se(swap_list_get(fname, &mp_list_head) >= 0);

        LIST_FOREACH(mount_point, m, mp_list_head)
        log_debug("path=%s o=%s f=0x%lx try-ro=%s dev=%u:%u",
                  m->path,
                  strempty(m->remount_options),
                  m->remount_flags,
                  yes_no(m->try_remount_ro),
                  major(m->devnum),
                  minor(m->devnum));
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_mount_points_list(NULL);
        test_mount_points_list("/test-umount/empty.mountinfo");
        test_mount_points_list("/test-umount/garbled.mountinfo");
        test_mount_points_list("/test-umount/rhbug-1554943.mountinfo");

        test_swap_list(NULL);
        test_swap_list("/test-umount/example.swaps");
}
