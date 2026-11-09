/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

_sync_ bool in_initrd(void);
void in_initrd_force(bool value);

int in_first_boot(void);
