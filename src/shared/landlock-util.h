/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

#if HAVE_LANDLOCK_CONFIG

#include <landlockconfig.h>
#include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(landlockconfig_parse_toml_directory);
extern DLSYM_PROTOTYPE(landlockconfig_build_ruleset);
extern DLSYM_PROTOTYPE(landlockconfig_free);

/*
 * Custom cleanup function because landlockconfig_* functions can return
 * negative error codes.
 */
static inline void sym_landlockconfig_freep(struct landlockconfig **p) {
        if (p && *p && (intptr_t) *p > 0) {
                sym_landlockconfig_free(*p);
                *p = NULL;
        }
}

int dlopen_landlockconfig(void);

int landlock_apply(const char *path);

#else /* HAVE_LANDLOCK_CONFIG */

static inline int dlopen_landlockconfig(void) {
        return -EOPNOTSUPP;
}

#endif /* HAVE_LANDLOCK_CONFIG */
