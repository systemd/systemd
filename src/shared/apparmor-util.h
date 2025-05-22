/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

#if HAVE_APPARMOR
#  include <sys/apparmor.h>

#  include "dlfcn-util.h"

extern DLSYM_PROTOTYPE(aa_change_onexec);
extern DLSYM_PROTOTYPE(aa_change_profile);
extern DLSYM_PROTOTYPE(aa_features_new_from_kernel);
extern DLSYM_PROTOTYPE(aa_features_unref);
extern DLSYM_PROTOTYPE(aa_policy_cache_dir_path_preview);
extern DLSYM_PROTOTYPE(aa_policy_cache_new);
extern DLSYM_PROTOTYPE(aa_policy_cache_replace_all);
extern DLSYM_PROTOTYPE(aa_policy_cache_unref);

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(aa_features*, sym_aa_features_unref, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(aa_policy_cache*, sym_aa_policy_cache_unref, NULL);

int dlopen_libapparmor(void);
#else
static inline int dlopen_libapparmor(void) {
        return -EOPNOTSUPP;
}
#endif

bool mac_apparmor_use(void);
