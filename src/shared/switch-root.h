/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
/***
  This file is part of systemd.

  Copyright 2012 Harald Hoyer, Lennart Poettering
***/

int switch_root(const char *new_root, const char *oldroot, bool detach_oldroot, unsigned long mountflags);
