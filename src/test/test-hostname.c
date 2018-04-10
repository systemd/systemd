/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

#include "hostname-setup.h"
#include "util.h"

int main(int argc, char* argv[]) {
        int r;

        r = hostname_setup();
        if (r < 0)
                log_error_errno(r, "hostname: %m");

        return 0;
}
