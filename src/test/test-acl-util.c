/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "acl-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-util.h"

TEST_RET(add_acls_for_user) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-empty.XXXXXX";
        _cleanup_close_ int fd = -EBADF;
        char *cmd;
        uid_t uid;
        int r;

        FOREACH_STRING(s, "capsh", "getfacl", "ls") {
                r = find_executable(s, /* ret_filename= */ NULL);
                if (r < 0)
                        return log_tests_skipped_errno(r, "Could not find %s binary: %m", s);
        }

        ASSERT_OK(fd = mkostemp_safe(fn));

        /* Use the mode that user journal files use */
        ASSERT_OK_ZERO_ERRNO(fchmod(fd, 0640));

        cmd = strjoina("ls -l ", fn);
        ASSERT_OK_ZERO_ERRNO(system(cmd));

        cmd = strjoina("getfacl -p ", fn);
        ASSERT_OK_ZERO_ERRNO(system(cmd));

        if (getuid() == 0 && !userns_has_single_user()) {
                r = get_user_creds(NOBODY_USER_NAME, /* flags= */ 0, /* ret_username= */ NULL, &uid, /* ret_gid= */ NULL, /* ret_home= */ NULL, /* ret_shell= */ NULL);
                if (r < 0)
                        uid = 0;
        } else
                uid = getuid();

        r = fd_add_uid_acl_permission(fd, uid, ACL_READ);
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return log_tests_skipped("no ACL support on /tmp");

        log_info_errno(r, "fd_add_uid_acl_permission(%i, "UID_FMT", ACL_READ): %m", fd, uid);
        ASSERT_OK(r);

        cmd = strjoina("ls -l ", fn);
        ASSERT_OK_ZERO_ERRNO(system(cmd));

        cmd = strjoina("getfacl -p ", fn);
        ASSERT_OK_ZERO_ERRNO(system(cmd));

        /* set the acls again */
        ASSERT_OK(fd_add_uid_acl_permission(fd, uid, ACL_READ));

        cmd = strjoina("ls -l ", fn);
        ASSERT_OK_ZERO_ERRNO(system(cmd));

        cmd = strjoina("getfacl -p ", fn);
        ASSERT_OK_ZERO_ERRNO(system(cmd));

        return 0;
}

TEST_RET(fd_acl_make_read_only) {
        _cleanup_(unlink_tempfilep) char fn[] = "/tmp/test-empty.XXXXXX";
        _cleanup_close_ int fd = -EBADF;
        const char *cmd;
        struct stat st;
        int r;

        FOREACH_STRING(s, "capsh", "getfacl", "ls", "stat") {
                r = find_executable(s, /* ret_filename= */ NULL);
                if (r < 0)
                        return log_tests_skipped_errno(r, "Could not find %s binary: %m", s);
        }

        ASSERT_OK(fd = mkostemp_safe(fn));

        /* make it more exciting */
        (void) fd_add_uid_acl_permission(fd, 1, ACL_READ|ACL_WRITE|ACL_EXECUTE);

        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_TRUE(FLAGS_SET(st.st_mode, 0200));

        cmd = strjoina("getfacl -p ", fn);
        ASSERT_OK_ZERO_ERRNO(system(cmd));

        cmd = strjoina("stat ", fn);
        ASSERT_OK_ZERO_ERRNO(system(cmd));

        log_info("read-only");
        ASSERT_OK_POSITIVE(fd_acl_make_read_only(fd));

        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_EQ(st.st_mode & 0222, 0000u);

        cmd = strjoina("getfacl -p ", fn);
        ASSERT_OK_ZERO_ERRNO(system(cmd));

        cmd = strjoina("stat ", fn);
        ASSERT_OK_ZERO_ERRNO(system(cmd));

        log_info("writable");
        ASSERT_OK_POSITIVE(fd_acl_make_writable(fd));

        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_EQ(st.st_mode & 0222, 0200u);

        cmd = strjoina("getfacl -p ", fn);
        ASSERT_OK_ZERO_ERRNO(system(cmd));

        cmd = strjoina("stat ", fn);
        ASSERT_OK_ZERO_ERRNO(system(cmd));

        log_info("read-only");
        ASSERT_OK_POSITIVE(fd_acl_make_read_only(fd));

        ASSERT_OK_ERRNO(fstat(fd, &st));
        ASSERT_EQ(st.st_mode & 0222, 0000u);

        cmd = strjoina("getfacl -p ", fn);
        ASSERT_OK_ZERO_ERRNO(system(cmd));

        cmd = strjoina("stat ", fn);
        ASSERT_OK_ZERO_ERRNO(system(cmd));

        return 0;
}

TEST_RET(acl_has_negative_permissions) {
        int r;

        r = dlopen_libacl(LOG_DEBUG);
        if (r < 0)
                return log_tests_skipped_errno(r, "libacl not available: %m");

        FOREACH_STRING(s,
                       "u::rwx,g::r-x,o::r-x",
                       "u::rwx,g::rwx,o::---",
                       "u::---,g::r-x,o::r-x",
                       "u::rwx,u:1000:r-x,g::r-x,g:1000:rwx,m::rwx,o::r-x") {
                _cleanup_(acl_freep) acl_t acl = NULL;

                ASSERT_NOT_NULL(acl = sym_acl_from_text(s));
                ASSERT_OK_ZERO(acl_has_negative_permissions(acl));
        }

        FOREACH_STRING(s,
                       "u::rwx,g::---,o::r-x",
                       "u::rwx,u:1000:---,g::r-x,m::r-x,o::r-x",
                       "u::rwx,g::r-x,g:1000:--x,m::r-x,o::r-x",
                       "u::rwx,u:1000:rwx,g::rwx,m::--x,o::r-x") {
                _cleanup_(acl_freep) acl_t acl = NULL;

                ASSERT_NOT_NULL(acl = sym_acl_from_text(s));
                ASSERT_OK_POSITIVE(acl_has_negative_permissions(acl));
        }

        return 0;
}

DEFINE_TEST_MAIN(LOG_INFO);
