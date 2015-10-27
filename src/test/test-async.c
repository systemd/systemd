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

#include <unistd.h>

#include "async.h"
#include "fileio.h"
#include "macro.h"
#include "util.h"

static bool test_async = false;

static void *async_func(void *arg) {
        test_async = true;

        return NULL;
}

int main(int argc, char *argv[]) {
        int fd;
        char name[] = "/tmp/test-asynchronous_close.XXXXXX";

        fd = mkostemp_safe(name, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        asynchronous_close(fd);

        assert_se(asynchronous_job(async_func, NULL) >= 0);

        assert_se(asynchronous_sync() >= 0);

        sleep(1);

        assert_se(fcntl(fd, F_GETFD) == -1);
        assert_se(test_async);

        unlink(name);

        return 0;
}
