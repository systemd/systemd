/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <linux/fiemap.h>
#include <stdio.h>

#include "fd-util.h"
#include "log.h"
#include "sleep-config.h"
#include "strv.h"
#include "util.h"

static int test_fiemap(const char *path) {
        _cleanup_free_ struct fiemap *fiemap = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0)
                return log_error_errno(errno, "failed to open %s: %m", path);
        r = read_fiemap(fd, &fiemap);
        if (r == -ENOTSUP) {
                log_info("Skipping test, not supported");
                exit(EXIT_TEST_SKIP);
        }
        if (r < 0)
                return log_error_errno(r, "Unable to read extent map for '%s': %m", path);
        log_info("extent map information for %s:", path);
        log_info("\t start: %llu", fiemap->fm_start);
        log_info("\t length: %llu", fiemap->fm_length);
        log_info("\t flags: %u", fiemap->fm_flags);
        log_info("\t number of mapped extents: %u", fiemap->fm_mapped_extents);
        log_info("\t extent count: %u", fiemap->fm_extent_count);
        if (fiemap->fm_extent_count > 0)
                log_info("\t first extent location: %llu",
                         fiemap->fm_extents[0].fe_physical / page_size());

        return 0;
}

static void test_sleep(void) {
        _cleanup_strv_free_ char
                **standby = strv_new("standby", NULL),
                **mem = strv_new("mem", NULL),
                **disk = strv_new("disk", NULL),
                **suspend = strv_new("suspend", NULL),
                **reboot = strv_new("reboot", NULL),
                **platform = strv_new("platform", NULL),
                **shutdown = strv_new("shutdown", NULL),
                **freez = strv_new("freeze", NULL);

        log_info("Standby configured: %s", yes_no(can_sleep_state(standby) > 0));
        log_info("Suspend configured: %s", yes_no(can_sleep_state(mem) > 0));
        log_info("Hibernate configured: %s", yes_no(can_sleep_state(disk) > 0));
        log_info("Hibernate+Suspend (Hybrid-Sleep) configured: %s", yes_no(can_sleep_disk(suspend) > 0));
        log_info("Hibernate+Reboot configured: %s", yes_no(can_sleep_disk(reboot) > 0));
        log_info("Hibernate+Platform configured: %s", yes_no(can_sleep_disk(platform) > 0));
        log_info("Hibernate+Shutdown configured: %s", yes_no(can_sleep_disk(shutdown) > 0));
        log_info("Freeze configured: %s", yes_no(can_sleep_state(freez) > 0));

        log_info("Suspend configured and possible: %s", yes_no(can_sleep("suspend") > 0));
        log_info("Hibernation configured and possible: %s", yes_no(can_sleep("hibernate") > 0));
        log_info("Hybrid-sleep configured and possible: %s", yes_no(can_sleep("hybrid-sleep") > 0));
        log_info("Suspend-then-Hibernate configured and possible: %s", yes_no(can_sleep("suspend-then-hibernate") > 0));
}

int main(int argc, char* argv[]) {
        int i, r = 0, k;

        log_parse_environment();
        log_open();

        if (getuid() != 0)
                log_warning("This program is unlikely to work for unprivileged users");

        test_sleep();

        if (argc <= 1)
                assert_se(test_fiemap(argv[0]) == 0);
        else
                for (i = 1; i < argc; i++) {
                        k = test_fiemap(argv[i]);
                        if (r == 0)
                                r = k;
                }

        return r;
}
