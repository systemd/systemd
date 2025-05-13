/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/reboot.h>
#include <sys/reboot.h>

/* glibc defines the reboot() API call, which is a wrapper around the system call of the same name, but without the
 * extra "arg" parameter. Since we need that parameter for some calls, let's add a "raw" wrapper that is defined the
 * same way, except it takes the additional argument. */

int raw_reboot(int cmd, const void *arg);
