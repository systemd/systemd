/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/reboot.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "raw-reboot.h"

int raw_reboot(int cmd, const void *arg) {
        return (int) syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, cmd, arg);
}
