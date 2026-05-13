/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"

void sigbus_install(void);
void sigbus_reset(void);

int sigbus_pop(void **ret);
