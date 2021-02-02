/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef struct Unit Unit;

int restrict_network_interfaces_supported(void);
int restrict_network_interfaces_install(Unit *u);
