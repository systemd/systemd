/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <dlfcn.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(void*, dlclose);
