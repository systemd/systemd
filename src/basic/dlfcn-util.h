/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dlfcn.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(void*, dlclose);

int dlsym_many_and_warn(void *dl, int level, ...);
