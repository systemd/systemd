/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2010 ProFUSION embedded systems
***/

#include <stdbool.h>

#include "umount.h"

int swapoff_all(bool *changed);

int swap_list_get(const char *swaps, MountPoint **head);
