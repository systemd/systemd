/* SPDX-License-Identifier: LGPL-2.1+ */

#include <unistd.h>

#include "plymouth-util.h"

bool plymouth_running(void) {
        return access("/run/plymouth/pid", F_OK) >= 0;
}
