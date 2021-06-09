/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"

#if HAVE_SELINUX

/* NOTE: This function should not be called directly,
 * only via mac_selinux_*_access_check() funtions.
 */
int mac_selinux_generic_access_check(
                sd_bus_message *message,
                const char *path,
                const char *class,
                const char *permission,
                sd_bus_error *error,
                const char *func);

#endif
