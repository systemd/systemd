/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "time-util.h"

int udev_parse_config_full(
                unsigned *ret_children_max,
                usec_t *ret_exec_delay_usec,
                usec_t *ret_event_timeout_usec);

static inline int udev_parse_config(void) {
        return udev_parse_config_full(NULL, NULL, NULL);
}
