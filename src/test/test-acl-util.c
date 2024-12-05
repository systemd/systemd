/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "acl-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "path-util.h"
#include "string-util.h"
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
                r = find_executable(s, NULL);
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
                const char *nobody = NOBODY_USER_NAME;
                r = get_user_creds(&nobody, &uid, NULL, NULL, NULL, 0);
                if (r < 0)
                        uid = 0;
        } else
                uid = getuid();

        r = fd_add_uid_acl_permission(fd, uid, ACL_READ);
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return log_tests_skipped("no ACL support on /tmp");

        log_info_errno(r, "fd_add_uid_acl_permission(%i, "UID_FMT", ACL_READ): %m", fd, uid);
        assert_se(r >= 0);

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
                r = find_executable(s, NULL);
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

DEFINE_TEST_MAIN(LOG_INFO);
