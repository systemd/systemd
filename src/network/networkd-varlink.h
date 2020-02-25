/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "networkd-manager.h"

int manager_open_varlink(Manager *s, const char *socket, int fd);
