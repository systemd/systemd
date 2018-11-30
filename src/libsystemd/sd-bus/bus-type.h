/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "macro.h"

bool bus_type_is_valid(char c) _const_;
bool bus_type_is_basic(char c) _const_;
/* "trivial" is systemd's term for what the D-Bus Specification calls
 * a "fixed type": that is, a basic type of fixed length */
bool bus_type_is_trivial(char c) _const_;
bool bus_type_is_container(char c) _const_;

int bus_type_get_alignment(char c) _const_;
int bus_type_get_size(char c) _const_;
