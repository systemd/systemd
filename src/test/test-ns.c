/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "namespace.h"

int main(int argc, char *argv[]) {
        const char * const writable[] = {
                "/home",
                NULL
        };

        const char * const readonly[] = {
                "/",
                "/usr",
                "/boot",
                NULL
        };

        const char *inaccessible[] = {
                "/home/lennart/projects",
                NULL
        };
        char *root_directory;
        char *projects_directory;

        int r;
        char tmp_dir[] = "/tmp/systemd-private-XXXXXX",
             var_tmp_dir[] = "/var/tmp/systemd-private-XXXXXX";

        assert_se(mkdtemp(tmp_dir));
        assert_se(mkdtemp(var_tmp_dir));

        root_directory = getenv("TEST_NS_CHROOT");
        projects_directory = getenv("TEST_NS_PROJECTS");

        if (projects_directory)
                inaccessible[0] = projects_directory;

        log_info("Inaccessible directory: '%s'", inaccessible[0]);
        if (root_directory)
                log_info("Chroot: '%s'", root_directory);
        else
                log_info("Not chrooted");

        r = setup_namespace(root_directory,
                            (char **) writable,
                            (char **) readonly,
                            (char **) inaccessible,
                            tmp_dir,
                            var_tmp_dir,
                            NULL,
                            true,
                            PROTECT_HOME_NO,
                            PROTECT_SYSTEM_NO,
                            0);
        if (r < 0) {
                log_error_errno(r, "Failed to setup namespace: %m");

                log_info("Usage:\n"
                         "  sudo TEST_NS_PROJECTS=/home/lennart/projects ./test-ns\n"
                         "  sudo TEST_NS_CHROOT=/home/alban/debian-tree TEST_NS_PROJECTS=/home/alban/debian-tree/home/alban/Documents ./test-ns");

                return 1;
        }

        execl("/bin/sh", "/bin/sh", NULL);
        log_error_errno(errno, "execl(): %m");

        return 1;
}
