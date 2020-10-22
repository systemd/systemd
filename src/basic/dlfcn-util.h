/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <dlfcn.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(void*, dlclose);

int dlsym_many_and_warn(void *dl, int level, ...);

/* Let's declare dlopen() deps in an ELF section that packaging tools can read out with "objcopy", and
 * transform into packaging dependencies */

#define DECLARE_DLOPEN_DEP(dep)                 \
        _DECLARE_DLOPEN_DEP(UNIQ, dep)

#define _DECLARE_DLOPEN_DEP(uq, dep)            \
        _section_("SYSTEMD_DLOPEN_DEP")         \
        _used_                                  \
        _alignptr_                              \
        _variable_no_sanitize_address_          \
        static const char UNIQ_T(dlopen_dep, uq)[] = dep
