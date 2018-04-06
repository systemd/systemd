/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

#include <stdio.h>
#include <string.h>

#include "log.h"
#include "loopback-setup.h"

int main(int argc, char* argv[]) {
        int r;

        log_open();
        log_set_max_level(LOG_DEBUG);
        log_parse_environment();

        r = loopback_setup();
        if (r < 0)
                log_error_errno(r, "loopback: %m");

        return r >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
