/***
  This file is part of systemd.

  Copyright 2015 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

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

        fd = mkostemp_safe(fn, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        /* Use the mode that user journal files use */
        assert_se(fchmod(fd, 0640) == 0);

        cmd = strjoina("ls -l ", fn);
        assert_se(system(cmd) == 0);

        cmd = strjoina("getfacl -p ", fn);
        assert_se(system(cmd) == 0);

        if (getuid() == 0) {
                const char *nobody = "nobody";
                r = get_user_creds(&nobody, &uid, NULL, NULL, NULL);
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
