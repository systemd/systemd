/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
***/

#include <stdio.h>

#include "log.h"
#include "sleep-config.h"
#include "strv.h"
#include "util.h"

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
        log_parse_environment();
        log_open();

        if (getuid() != 0)
                log_warning("This program is unlikely to work for unprivileged users");

        test_sleep();

        return 0;
}
