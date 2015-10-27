/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "formats-util.h"
#include "string-util.h"
#include "util.h"

int main(int argc, char** argv) {
        const char *p = argv[1] ?: "/tmp";
        char *pattern = strjoina(p, "/systemd-test-XXXXXX");
        _cleanup_close_ int fd, fd2;
        _cleanup_free_ char *cmd, *cmd2;

        fd = open_tmpfile(p, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        assert_se(asprintf(&cmd, "ls -l /proc/"PID_FMT"/fd/%d", getpid(), fd) > 0);
        system(cmd);

        fd2 = mkostemp_safe(pattern, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);
        assert_se(unlink(pattern) == 0);

        assert_se(asprintf(&cmd2, "ls -l /proc/"PID_FMT"/fd/%d", getpid(), fd2) > 0);
        system(cmd2);

        return 0;
}
