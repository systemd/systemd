/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

void sigbus_install(void);
void sigbus_reset(void);

void sigbus_push(void *addr);
int sigbus_pop(void **ret);
