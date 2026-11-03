/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "chown-recursive.h"
#include "errno-util.h"
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
        ASSERT_OK(mkdtemp_malloc(/* template= */ NULL, &t));

        p = strjoina(t, "/dir");
        ASSERT_OK_ERRNO(mkdir(p, 0777));
        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_TRUE(S_ISDIR(st.st_mode));
        ASSERT_EQ(st.st_mode & 07777, 0755U);
        ASSERT_EQ(st.st_uid, uid);
        ASSERT_EQ(st.st_gid, gid);
        ASSERT_FALSE(has_xattr(p));

        p = strjoina(t, "/dir/symlink");
        ASSERT_OK_ERRNO(symlink("../../", p));
        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_TRUE(S_ISLNK(st.st_mode));
        ASSERT_EQ(st.st_mode & 07777, 0777U);
        ASSERT_EQ(st.st_uid, uid);
        ASSERT_EQ(st.st_gid, gid);
        ASSERT_FALSE(has_xattr(p));

        p = strjoina(t, "/dir/reg");
        ASSERT_OK_ERRNO(mknod(p, S_IFREG|0777, 0));
        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_TRUE(S_ISREG(st.st_mode));
        ASSERT_EQ(st.st_mode & 07777, 0755U);
        ASSERT_EQ(st.st_uid, uid);
        ASSERT_EQ(st.st_gid, gid);
        ASSERT_FALSE(has_xattr(p));

        p = strjoina(t, "/dir/sock");
        ASSERT_OK_ERRNO(mknod(p, S_IFSOCK|0777, 0));
        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_TRUE(S_ISSOCK(st.st_mode));
        ASSERT_EQ(st.st_mode & 07777, 0755U);
        ASSERT_EQ(st.st_uid, uid);
        ASSERT_EQ(st.st_gid, gid);
        ASSERT_FALSE(has_xattr(p));

        p = strjoina(t, "/dir/fifo");
        ASSERT_OK_ERRNO(mknod(p, S_IFIFO|0777, 0));
        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_TRUE(S_ISFIFO(st.st_mode));
        ASSERT_EQ(st.st_mode & 07777, 0755U);
        ASSERT_EQ(st.st_uid, uid);
        ASSERT_EQ(st.st_gid, gid);
        ASSERT_FALSE(has_xattr(p));

        /* We now apply an xattr to the dir, and check it again */
        p = strjoina(t, "/dir");
        r = RET_NERRNO(setxattr(p, "system.posix_acl_access", acl, sizeof(acl), 0));
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return (void) log_tests_skipped_errno(r, "no acl supported on /tmp");

        ASSERT_OK(r);
        ASSERT_OK_ERRNO(setxattr(p, "system.posix_acl_default", default_acl, sizeof(default_acl), 0));
        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_TRUE(S_ISDIR(st.st_mode));
        ASSERT_EQ(st.st_mode & 07777, 0775U); /* acl change changed the mode too */
        ASSERT_EQ(st.st_uid, uid);
        ASSERT_EQ(st.st_gid, gid);
        ASSERT_TRUE(has_xattr(p));

        ASSERT_OK(path_chown_recursive(t, 1, 2, 07777, /* flags= */ 0));

        p = strjoina(t, "/dir");
        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_TRUE(S_ISDIR(st.st_mode));
        ASSERT_EQ(st.st_mode & 07777, 0775U);
        ASSERT_EQ(st.st_uid, 1U);
        ASSERT_EQ(st.st_gid, 2U);
        ASSERT_FALSE(has_xattr(p));

        p = strjoina(t, "/dir/symlink");
        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_TRUE(S_ISLNK(st.st_mode));
        ASSERT_EQ(st.st_mode & 07777, 0777U);
        ASSERT_EQ(st.st_uid, 1U);
        ASSERT_EQ(st.st_gid, 2U);
        ASSERT_FALSE(has_xattr(p));

        p = strjoina(t, "/dir/reg");
        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_TRUE(S_ISREG(st.st_mode));
        ASSERT_EQ(st.st_mode & 07777, 0755U);
        ASSERT_EQ(st.st_uid, 1U);
        ASSERT_EQ(st.st_gid, 2U);
        ASSERT_FALSE(has_xattr(p));

        p = strjoina(t, "/dir/sock");
        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_TRUE(S_ISSOCK(st.st_mode));
        ASSERT_EQ(st.st_mode & 07777, 0755U);
        ASSERT_EQ(st.st_uid, 1U);
        ASSERT_EQ(st.st_gid, 2U);
        ASSERT_FALSE(has_xattr(p));

        p = strjoina(t, "/dir/fifo");
        ASSERT_OK_ERRNO(lstat(p, &st));
        ASSERT_TRUE(S_ISFIFO(st.st_mode));
        ASSERT_EQ(st.st_mode & 07777, 0755U);
        ASSERT_EQ(st.st_uid, 1U);
        ASSERT_EQ(st.st_gid, 2U);
        ASSERT_FALSE(has_xattr(p));
}

static int intro(void) {
        if (geteuid() != 0 || userns_has_single_user())
                return log_tests_skipped("not running as root or in userns with single user");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
