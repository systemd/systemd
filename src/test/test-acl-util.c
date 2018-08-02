/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "acl-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "string-util.h"
#include "user-util.h"

static void test_add_acls_for_user(void) {
        char fn[] = "/tmp/test-empty.XXXXXX";
        _cleanup_close_ int fd = -1;
        char *cmd;
        uid_t uid;
        int r;

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

        r = add_acls_for_user(fd, uid);
        assert_se(r >= 0);

        cmd = strjoina("ls -l ", fn);
        assert_se(system(cmd) == 0);

        cmd = strjoina("getfacl -p ", fn);
        assert_se(system(cmd) == 0);

        /* set the acls again */

        r = add_acls_for_user(fd, uid);
        assert_se(r >= 0);

        cmd = strjoina("ls -l ", fn);
        assert_se(system(cmd) == 0);

        cmd = strjoina("getfacl -p ", fn);
        assert_se(system(cmd) == 0);

        unlink(fn);
}

int main(int argc, char **argv) {
        test_add_acls_for_user();

        return 0;
}
