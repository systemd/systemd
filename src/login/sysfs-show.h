/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright 2011 Lennart Poettering
***/

#include <sys/types.h>

#include "output-mode.h"

int show_sysfs(const char *seat, const char *prefix, unsigned columns, OutputFlags flags);
