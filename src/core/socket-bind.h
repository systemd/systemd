/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "unit.h"

int socket_bind_supported(void);

int socket_bind_install(Unit *u);
