/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2010 ProFUSION embedded systems
***/

#include "shared-forward.h"
#include "list.h"

#if HAVE_LIBMOUNT
int swapoff_all(bool *changed);

/* This is exported just for testing */
typedef struct SwapDevice {
        char *path;
        LIST_FIELDS(struct SwapDevice, swap_device);
} SwapDevice;

int swap_list_get(const char *swaps, SwapDevice **head);
void swap_devices_list_free(SwapDevice **head);

#else

static inline int swapoff_all(bool *changed) {
        return -EOPNOTSUPP;
}
#endif
