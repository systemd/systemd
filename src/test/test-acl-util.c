/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "acl-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "user-util.h"

static int test_add_acls_for_user(void) {
        char fn[] = "/tmp/test-empty.XXXXXX";
        _cleanup_close_ int fd = -1;
        char *cmd;
        uid_t uid;
        int r;

        log_info("/* %s */", __func__);

        fd = mkostemp_safe(fn);
        assert_se(fd >= 0);

        /* Use the mode that user journal files use */
        assert_se(fchmod(fd, 0640) == 0);

        cmd = strjoina("ls -l ", fn);
        assert_se(system(cmd) == 0);

        cmd = strjoina("getfacl -p ", fn);
        assert_se(system(cmd) == 0);

        if (getuid() == 0) {
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
        assert_se(system(cmd) == 0);

        cmd = strjoina("getfacl -p ", fn);
        assert_se(system(cmd) == 0);

        /* set the acls again */

        r = fd_add_uid_acl_permission(fd, uid, ACL_READ);
        assert_se(r >= 0);

        cmd = strjoina("ls -l ", fn);
        assert_se(system(cmd) == 0);

        cmd = strjoina("getfacl -p ", fn);
        assert_se(system(cmd) == 0);

        (void) unlink(fn);
        return 0;
}

int main(int argc, char **argv) {
        return test_add_acls_for_user();
}
