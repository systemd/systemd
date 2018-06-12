/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright 2014 Lennart Poettering
***/

void sigbus_install(void);
void sigbus_reset(void);

int sigbus_pop(void **ret);
