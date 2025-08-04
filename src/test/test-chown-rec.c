/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "chown-recursive.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

static const uint8_t acl[] = {
        0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x07, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x07, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x10, 0x00, 0x07, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x20, 0x00, 0x05, 0x00,
        0xff, 0xff, 0xff, 0xff,
};

static const uint8_t default_acl[] = {
        0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x07, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x04, 0x00, 0x07, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x08, 0x00, 0x07, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x07, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x20, 0x00, 0x05, 0x00,
        0xff, 0xff, 0xff, 0xff,
};

static bool has_xattr(const char *p) {
        char buffer[sizeof(acl) * 4];

        if (lgetxattr(p, "system.posix_acl_access", buffer, sizeof(buffer)) < 0)
                return !ERRNO_IS_XATTR_ABSENT(errno);

        return true;
}

TEST(chown_recursive) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        struct stat st;
        const char *p;
        const uid_t uid = getuid();
        const gid_t gid = getgid();
        int r;

        umask(022);
        assert_se(mkdtemp_malloc(NULL, &t) >= 0);

        p = strjoina(t, "/dir");
        assert_se(mkdir(p, 0777) >= 0);
        assert_se(lstat(p, &st) >= 0);
        assert_se(S_ISDIR(st.st_mode));
        assert_se((st.st_mode & 07777) == 0755);
        assert_se(st.st_uid == uid);
        assert_se(st.st_gid == gid);
        assert_se(!has_xattr(p));

        p = strjoina(t, "/dir/symlink");
        assert_se(symlink("../../", p) >= 0);
        assert_se(lstat(p, &st) >= 0);
        assert_se(S_ISLNK(st.st_mode));
        assert_se((st.st_mode & 07777) == 0777);
        assert_se(st.st_uid == uid);
        assert_se(st.st_gid == gid);
        assert_se(!has_xattr(p));

        p = strjoina(t, "/dir/reg");
        assert_se(mknod(p, S_IFREG|0777, 0) >= 0);
        assert_se(lstat(p, &st) >= 0);
        assert_se(S_ISREG(st.st_mode));
        assert_se((st.st_mode & 07777) == 0755);
        assert_se(st.st_uid == uid);
        assert_se(st.st_gid == gid);
        assert_se(!has_xattr(p));

        p = strjoina(t, "/dir/sock");
        assert_se(mknod(p, S_IFSOCK|0777, 0) >= 0);
        assert_se(lstat(p, &st) >= 0);
        assert_se(S_ISSOCK(st.st_mode));
        assert_se((st.st_mode & 07777) == 0755);
        assert_se(st.st_uid == uid);
        assert_se(st.st_gid == gid);
        assert_se(!has_xattr(p));

        p = strjoina(t, "/dir/fifo");
        assert_se(mknod(p, S_IFIFO|0777, 0) >= 0);
        assert_se(lstat(p, &st) >= 0);
        assert_se(S_ISFIFO(st.st_mode));
        assert_se((st.st_mode & 07777) == 0755);
        assert_se(st.st_uid == uid);
        assert_se(st.st_gid == gid);
        assert_se(!has_xattr(p));

        /* We now apply an xattr to the dir, and check it again */
        p = strjoina(t, "/dir");
        r = RET_NERRNO(setxattr(p, "system.posix_acl_access", acl, sizeof(acl), 0));
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return (void) log_tests_skipped_errno(r, "no acl supported on /tmp");

        assert_se(r >= 0);
        assert_se(setxattr(p, "system.posix_acl_default", default_acl, sizeof(default_acl), 0) >= 0);
        assert_se(lstat(p, &st) >= 0);
        assert_se(S_ISDIR(st.st_mode));
        assert_se((st.st_mode & 07777) == 0775); /* acl change changed the mode too */
        assert_se(st.st_uid == uid);
        assert_se(st.st_gid == gid);
        assert_se(has_xattr(p));

        assert_se(path_chown_recursive(t, 1, 2, 07777, 0) >= 0);

        p = strjoina(t, "/dir");
        assert_se(lstat(p, &st) >= 0);
        assert_se(S_ISDIR(st.st_mode));
        assert_se((st.st_mode & 07777) == 0775);
        assert_se(st.st_uid == 1);
        assert_se(st.st_gid == 2);
        assert_se(!has_xattr(p));

        p = strjoina(t, "/dir/symlink");
        assert_se(lstat(p, &st) >= 0);
        assert_se(S_ISLNK(st.st_mode));
        assert_se((st.st_mode & 07777) == 0777);
        assert_se(st.st_uid == 1);
        assert_se(st.st_gid == 2);
        assert_se(!has_xattr(p));

        p = strjoina(t, "/dir/reg");
        assert_se(lstat(p, &st) >= 0);
        assert_se(S_ISREG(st.st_mode));
        assert_se((st.st_mode & 07777) == 0755);
        assert_se(st.st_uid == 1);
        assert_se(st.st_gid == 2);
        assert_se(!has_xattr(p));

        p = strjoina(t, "/dir/sock");
        assert_se(lstat(p, &st) >= 0);
        assert_se(S_ISSOCK(st.st_mode));
        assert_se((st.st_mode & 07777) == 0755);
        assert_se(st.st_uid == 1);
        assert_se(st.st_gid == 2);
        assert_se(!has_xattr(p));

        p = strjoina(t, "/dir/fifo");
        assert_se(lstat(p, &st) >= 0);
        assert_se(S_ISFIFO(st.st_mode));
        assert_se((st.st_mode & 07777) == 0755);
        assert_se(st.st_uid == 1);
        assert_se(st.st_gid == 2);
        assert_se(!has_xattr(p));
}

static int intro(void) {
        if (geteuid() != 0 || userns_has_single_user())
                return log_tests_skipped("not running as root or in userns with single user");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
