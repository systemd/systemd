/* SPDX-License-Identifier: LGPL-2.1+ */

#include <unistd.h>

#include "tomoyo-util.h"

bool mac_tomoyo_use(void) {
        static int cached_use = -1;

        if (cached_use < 0)
                cached_use = (access("/sys/kernel/security/tomoyo/version",
                                     F_OK) == 0);

        return cached_use;
}
