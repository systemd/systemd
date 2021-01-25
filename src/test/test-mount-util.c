/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>

#include "alloc-util.h"
#include "env-util.h"
#include "fs-util.h"
#include "macro.h"
#include "mkdir.h"
#include "mount-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-util.h"

static void test_mount_option_mangle(void) {
        char *opts = NULL;
        unsigned long f;

        assert_se(mount_option_mangle(NULL, MS_RDONLY|MS_NOSUID, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID));
        assert_se(opts == NULL);

        assert_se(mount_option_mangle("", MS_RDONLY|MS_NOSUID, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID));
        assert_se(opts == NULL);

        assert_se(mount_option_mangle("ro,nosuid,nodev,noexec", 0, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC));
        assert_se(opts == NULL);

        assert_se(mount_option_mangle("ro,nosuid,nodev,noexec,mode=755", 0, &f, &opts) == 0);
        assert_se(f == (MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC));
        assert_se(streq(opts, "mode=755"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,nosuid,foo,hogehoge,nodev,mode=755", 0, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV));
        assert_se(streq(opts, "foo,hogehoge,mode=755"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,nosuid,nodev,noexec,relatime,net_cls,net_prio", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RELATIME));
        assert_se(streq(opts, "net_cls,net_prio"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,nosuid,nodev,relatime,size=1630748k,mode=700,uid=1000,gid=1000", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV|MS_RELATIME));
        assert_se(streq(opts, "size=1630748k,mode=700,uid=1000,gid=1000"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("size=1630748k,rw,gid=1000,,,nodev,relatime,,mode=700,nosuid,uid=1000", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV|MS_RELATIME));
        assert_se(streq(opts, "size=1630748k,gid=1000,mode=700,uid=1000"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,exec,size=8143984k,nr_inodes=2035996,mode=755", MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV, &f, &opts) == 0);
        assert_se(f == (MS_NOSUID|MS_NODEV));
        assert_se(streq(opts, "size=8143984k,nr_inodes=2035996,mode=755"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,relatime,fmask=0022,,,dmask=0022", MS_RDONLY, &f, &opts) == 0);
        assert_se(f == MS_RELATIME);
        assert_se(streq(opts, "fmask=0022,dmask=0022"));
        opts = mfree(opts);

        assert_se(mount_option_mangle("rw,relatime,fmask=0022,dmask=0022,\"hogehoge", MS_RDONLY, &f, &opts) < 0);
}

static void test_overlay(void) {
        _cleanup_(rm_rf_physical_and_freep) char *d = NULL;
        _cleanup_strv_free_ char **mounts_list = NULL, **overlays_list = NULL;
        char *p, *q, **s;

        log_info("/* %s */", __func__);

        assert_se(mkdtemp_malloc(NULL, &d) >= 0);

        p = strjoina(d, "/root/opt");
        assert_se(mkdir_p(p, 0755) >= 0);
        p = strjoina(d, "/extra/opt");
        assert_se(mkdir_p(p, 0755) >= 0);
        p = strjoina(d, "/root");
        q = strjoina(d, "/extra");
        assert_se(mount_compute_shallow_overlays(p, q, &mounts_list, &overlays_list) >= 0);
        assert_se(strv_isempty(mounts_list));
        assert_se(strv_isempty(overlays_list));

        p = strjoina(d, "/root/var/opt");
        assert_se(mkdir_p(p, 0755) >= 0);
        p = strjoina(d, "/root/opt/original");
        assert_se(mkdir_p(p, 0755) >= 0);
        p = strjoina(d, "/root/opt/unused");
        assert_se(mkdir_p(p, 0755) >= 0);
        p = strjoina(d, "/root/opt/overwritten");
        assert_se(touch_file(p, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID) >= 0);
        p = strjoina(d, "/root/etc/os-release");
        assert_se(touch_file(p, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID) >= 0);
        p = strjoina(d, "/root/usr/lib/os-release");
        assert_se(touch_file(p, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID) >= 0);
        p = strjoina(d, "/root/usr/lib/a_file");
        assert_se(touch_file(p, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID) >= 0);
        p = strjoina(d, "/extra/usr/lib");
        assert_se(mkdir_p(p, 0755) >= 0);
        p = strjoina(d, "/extra/usr/lib/a_file");
        assert_se(touch_file(p, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID) >= 0);
        p = strjoina(d, "/extra/usr/lib/newdir");
        assert_se(mkdir_p(p, 0755) >= 0);
        p = strjoina(d, "/extra/usr/lib/newdir/a");
        assert_se(mkdir_p(p, 0755) >= 0);
        p = strjoina(d, "/extra/usr/lib/newdir/b/1");
        assert_se(touch_file(p, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID) >= 0);
        p = strjoina(d, "/extra/usr/lib/os-release");
        assert_se(touch_file(p, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID) >= 0);
        p = strjoina(d, "/extra/usr/lib/extension-release.d");
        assert_se(mkdir_p(p, 0755) >= 0);
        p = strjoina(d, "/extra/usr/lib/newdir/b/2");
        assert_se(touch_file(p, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID) >= 0);
        p = strjoina(d, "/extra/opt/original/extension_file");
        assert_se(touch_file(p, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID) >= 0);
        p = strjoina(d, "/extra/opt/original/extension_dir");
        assert_se(mkdir_p(p, 0755) >= 0);
        p = strjoina(d, "/extra/opt/original/extension_dir/c");
        assert_se(touch_file(p, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID) >= 0);
        p = strjoina(d, "/extra/opt/overwritten");
        assert_se(touch_file(p, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID) >= 0);
        p = strjoina(d, "/extra/usr/lib/extra_file");
        assert_se(touch_file(p, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID) >= 0);

        p = strjoina(d, "/root");
        q = strjoina(d, "/extra");
        assert_se(mount_compute_shallow_overlays(p, q, &mounts_list, &overlays_list) >= 0);

        /* Depending on the filesystem, traversal order changes - sort the vectors */
        strv_sort(mounts_list);

        s = STRV_MAKE("/opt/original", "/opt/overwritten");
        assert_se(strv_equal(s, mounts_list));
        s = STRV_MAKE("/usr/lib");
        assert_se(strv_equal(s, overlays_list));
        strv_free(TAKE_PTR(mounts_list));
        strv_free(TAKE_PTR(overlays_list));

        /* clash: one has file, other has directory at the same path */
        p = strjoina(d, "/extra/opt/unused");
        assert_se(touch_file(p, true, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID) >= 0);

        p = strjoina(d, "/root");
        q = strjoina(d, "/extra");
        assert_se(mount_compute_shallow_overlays(p, q, &mounts_list, &overlays_list) == -EINVAL);

        /* empty extra */
        strv_free(TAKE_PTR(mounts_list));
        strv_free(TAKE_PTR(overlays_list));
        p = strjoina(d, "/empty");
        assert_se(mkdir_p(p, 0755) >= 0);
        p = strjoina(d, "/root");
        q = strjoina(d, "/empty");
        assert_se(mount_compute_shallow_overlays(p, q, &mounts_list, &overlays_list) >= 0);
        assert_se(strv_isempty(mounts_list));
        assert_se(strv_isempty(overlays_list));

        /* empty root - unrealistic corner case, but cover it just in case */
        strv_free(TAKE_PTR(mounts_list));
        strv_free(TAKE_PTR(overlays_list));
        p = strjoina(d, "/empty");
        q = strjoina(d, "/extra");
        assert_se(mount_compute_shallow_overlays(p, q, &mounts_list, &overlays_list) >= 0);
        strv_sort(mounts_list);
        s = STRV_MAKE("/");
        assert_se(strv_equal(s, mounts_list));
        assert_se(strv_isempty(overlays_list));

        /* both empty */
        strv_free(TAKE_PTR(mounts_list));
        strv_free(TAKE_PTR(overlays_list));
        p = strjoina(d, "/empty");
        q = strjoina(d, "/empty");
        assert_se(mount_compute_shallow_overlays(p, q, &mounts_list, &overlays_list) >= 0);
        assert_se(strv_isempty(mounts_list));
        assert_se(strv_isempty(overlays_list));
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_mount_option_mangle();
        test_overlay();

        return 0;
}
