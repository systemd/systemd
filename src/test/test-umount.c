/* SPDX-License-Identifier: LGPL-2.1+ */

#include "log.h"
#include "string-util.h"
#include "tests.h"
#include "umount.h"
#include "util.h"

static void test_mount_points_list(const char *fname) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, mp_list_head);
        MountPoint *m;

        log_info("/* %s(\"%s\") */", __func__, fname ?: "/proc/self/mountinfo");

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

static void test_swap_list(const char *fname) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, mp_list_head);
        MountPoint *m;

        log_info("/* %s(\"%s\") */", __func__, fname ?: "/proc/swaps");

        LIST_HEAD_INIT(mp_list_head);
        assert_se(swap_list_get(fname, &mp_list_head) >= 0);

        LIST_FOREACH(mount_point, m, mp_list_head)
                log_debug("path=%s o=%s f=0x%lx try-ro=%s dev=%u:%u",
                          m->path,
                          strempty(m->remount_options),
                          m->remount_flags,
                          yes_no(m->try_remount_ro),
                          major(m->devnum), minor(m->devnum));
}

int main(int argc, char **argv) {
        log_set_max_level(LOG_DEBUG);
        log_parse_environment();
        log_open();

        test_mount_points_list(NULL);
        test_mount_points_list(get_testdata_dir("/test-umount/empty.mountinfo"));
        test_mount_points_list(get_testdata_dir("/test-umount/garbled.mountinfo"));
        test_mount_points_list(get_testdata_dir("/test-umount/rhbug-1554943.mountinfo"));

        test_swap_list(NULL);
        test_swap_list(get_testdata_dir("/test-umount/example.swaps"));
}
