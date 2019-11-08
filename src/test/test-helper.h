/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2013 Holger Hans Peter Freyther
***/

#include "sd-daemon.h"

#define TEST_REQ_RUNNING_SYSTEMD(x)                                 \
        if (sd_booted() > 0) {                                      \
                x;                                                  \
        } else {                                                    \
                printf("systemd not booted skipping '%s'\n", #x);   \
        }

int enter_cgroup_subroot(void);
