/***
  This file is part of systemd

  Copyright 2014 Ronny Chevalier

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
#include <unistd.h>

#include "fdset.h"
#include "util.h"
#include "macro.h"

static void test_fdset_new_fill(void) {
        int fd = -1;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        char name[] = "/tmp/test-fdset_new_fill.XXXXXX";

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(fdset_new_fill(&fdset) >= 0);
        assert_se(fdset_contains(fdset, fd));

        unlink(name);
}

static void test_fdset_put_dup(void) {
        _cleanup_close_ int fd = -1;
        int copyfd = -1;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        char name[] = "/tmp/test-fdset_put_dup.XXXXXX";

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        fdset = fdset_new();
        assert_se(fdset);
        copyfd = fdset_put_dup(fdset, fd);
        assert_se(copyfd >= 0 && copyfd != fd);
        assert_se(fdset_contains(fdset, copyfd));
        assert_se(!fdset_contains(fdset, fd));

        unlink(name);
}

static void test_fdset_cloexec(void) {
        int fd = -1;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        int flags = -1;
        char name[] = "/tmp/test-fdset_cloexec.XXXXXX";

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        fdset = fdset_new();
        assert_se(fdset);
        assert_se(fdset_put(fdset, fd));

        assert_se(fdset_cloexec(fdset, false) >= 0);
        flags = fcntl(fd, F_GETFD);
        assert_se(flags >= 0);
        assert_se(!(flags & FD_CLOEXEC));

        assert_se(fdset_cloexec(fdset, true) >= 0);
        flags = fcntl(fd, F_GETFD);
        assert_se(flags >= 0);
        assert_se(flags & FD_CLOEXEC);

        unlink(name);
}

static void test_fdset_close_others(void) {
        int fd = -1;
        int copyfd = -1;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        int flags = -1;
        char name[] = "/tmp/test-fdset_close_others.XXXXXX";

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        fdset = fdset_new();
        assert_se(fdset);
        copyfd = fdset_put_dup(fdset, fd);
        assert_se(copyfd >= 0);

        assert_se(fdset_close_others(fdset) >= 0);
        flags = fcntl(fd, F_GETFD);
        assert_se(flags < 0);
        flags = fcntl(copyfd, F_GETFD);
        assert_se(flags >= 0);

        unlink(name);
}

static void test_fdset_remove(void) {
        _cleanup_close_ int fd = -1;
        FDSet *fdset = NULL;
        char name[] = "/tmp/test-fdset_remove.XXXXXX";

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        fdset = fdset_new();
        assert_se(fdset);
        assert_se(fdset_put(fdset, fd) >= 0);
        assert_se(fdset_remove(fdset, fd) >= 0);
        assert_se(!fdset_contains(fdset, fd));
        fdset_free(fdset);

        assert_se(fcntl(fd, F_GETFD) >= 0);

        unlink(name);
}

static void test_fdset_iterate(void) {
        int fd = -1;
        FDSet *fdset = NULL;
        char name[] = "/tmp/test-fdset_iterate.XXXXXX";
        Iterator i;
        int c = 0;
        int a;

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        fdset = fdset_new();
        assert_se(fdset);
        assert_se(fdset_put(fdset, fd) >= 0);
        assert_se(fdset_put(fdset, fd) >= 0);
        assert_se(fdset_put(fdset, fd) >= 0);

        FDSET_FOREACH(a, fdset, i) {
                c++;
                assert_se(a == fd);
        }
        assert_se(c == 1);

        fdset_free(fdset);

        unlink(name);
}

static void test_fdset_isempty(void) {
        int fd;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        char name[] = "/tmp/test-fdset_isempty.XXXXXX";

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        fdset = fdset_new();
        assert_se(fdset);

        assert_se(fdset_isempty(fdset));
        assert_se(fdset_put(fdset, fd) >= 0);
        assert_se(!fdset_isempty(fdset));

        unlink(name);
}

static void test_fdset_steal_first(void) {
        int fd;
        _cleanup_fdset_free_ FDSet *fdset = NULL;
        char name[] = "/tmp/test-fdset_steal_first.XXXXXX";

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        fdset = fdset_new();
        assert_se(fdset);

        assert_se(fdset_steal_first(fdset) < 0);
        assert_se(fdset_put(fdset, fd) >= 0);
        assert_se(fdset_steal_first(fdset) == fd);
        assert_se(fdset_steal_first(fdset) < 0);
        assert_se(fdset_put(fdset, fd) >= 0);

        unlink(name);
}

static void test_fdset_new_array(void) {
        int fds[] = {10, 11, 12, 13};
        _cleanup_fdset_free_ FDSet *fdset = NULL;

        assert_se(fdset_new_array(&fdset, fds, 4) >= 0);
        assert_se(fdset_size(fdset) == 4);
        assert_se(fdset_contains(fdset, 10));
        assert_se(fdset_contains(fdset, 11));
        assert_se(fdset_contains(fdset, 12));
        assert_se(fdset_contains(fdset, 13));
}

int main(int argc, char *argv[]) {
        test_fdset_new_fill();
        test_fdset_put_dup();
        test_fdset_cloexec();
        test_fdset_close_others();
        test_fdset_remove();
        test_fdset_iterate();
        test_fdset_isempty();
        test_fdset_steal_first();
        test_fdset_new_array();

        return 0;
}
