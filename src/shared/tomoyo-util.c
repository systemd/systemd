/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2017 Shawn Landden
***/

#include <unistd.h>

#include "tomoyo-util.h"

bool mac_tomoyo_use(void) {
        static int cached_use = -1;

        if (cached_use < 0)
                cached_use = (access("/sys/kernel/security/tomoyo/version",
                                     F_OK) == 0);

        return cached_use;
}
