/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

int switch_root(const char *new_root, const char *oldroot, bool detach_oldroot, unsigned long mountflags);
