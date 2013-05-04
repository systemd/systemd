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

int main(int argc, char* argv[]) {
        _cleanup_strv_free_ char
                **standby = strv_new("standby", NULL),
                **mem = strv_new("mem", NULL),
                **disk = strv_new("disk", NULL),
                **suspend = strv_new("suspend", NULL),
                **reboot = strv_new("reboot", NULL),
                **platform = strv_new("platform", NULL),
                **shutdown = strv_new("shutdown", NULL),
                **freez = strv_new("freeze", NULL);

        log_info("Can Standby: %s", yes_no(can_sleep_state(standby) > 0));
        log_info("Can Suspend: %s", yes_no(can_sleep_state(mem) > 0));
        log_info("Can Hibernate: %s", yes_no(can_sleep_state(disk) > 0));
        log_info("Can Hibernate+Suspend (Hybrid-Sleep): %s", yes_no(can_sleep_disk(suspend) > 0));
        log_info("Can Hibernate+Reboot: %s", yes_no(can_sleep_disk(reboot) > 0));
        log_info("Can Hibernate+Platform: %s", yes_no(can_sleep_disk(platform) > 0));
        log_info("Can Hibernate+Shutdown: %s", yes_no(can_sleep_disk(shutdown) > 0));
        log_info("Can Freeze: %s", yes_no(can_sleep_disk(freez) > 0));

        log_info("Suspend configured and possible: %s", yes_no(can_sleep("suspend") > 0));
        log_info("Hibernation configured and possible: %s", yes_no(can_sleep("hibernate") > 0));
        log_info("Hybrid-sleep configured and possible: %s", yes_no(can_sleep("hybrid-sleep") > 0));

        return 0;
}
