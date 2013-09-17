/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#include "util.h"
#include "log.h"
#include "sleep-config.h"
#include "strv.h"

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
}

int main(int argc, char* argv[]) {
        log_parse_environment();
        log_open();

        if (getuid() != 0)
                log_warning("This program is unlikely to work for unpriviledged users");

        test_sleep();

        return 0;
}
