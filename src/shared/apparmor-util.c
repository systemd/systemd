/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <syslog.h>

#include "alloc-util.h"
#include "apparmor-util.h"
#include "fileio.h"
#include "parse-util.h"

#if HAVE_APPARMOR
static void *libapparmor_dl = NULL;

DLSYM_PROTOTYPE(aa_change_onexec) = NULL;
DLSYM_PROTOTYPE(aa_change_profile) = NULL;
DLSYM_PROTOTYPE(aa_features_new_from_kernel) = NULL;
DLSYM_PROTOTYPE(aa_features_unref) = NULL;
DLSYM_PROTOTYPE(aa_policy_cache_dir_path_preview) = NULL;
DLSYM_PROTOTYPE(aa_policy_cache_new) = NULL;
DLSYM_PROTOTYPE(aa_policy_cache_replace_all) = NULL;
DLSYM_PROTOTYPE(aa_policy_cache_unref) = NULL;

int dlopen_libapparmor(void) {
        ELF_NOTE_DLOPEN("apparmor",
                        "Support for AppArmor policies",
                        ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED,
                        "libapparmor.so.1");

        return dlopen_many_sym_or_warn(
                        &libapparmor_dl,
                        "libapparmor.so.1",
                        LOG_DEBUG,
                        DLSYM_ARG(aa_change_onexec),
                        DLSYM_ARG(aa_change_profile),
                        DLSYM_ARG(aa_features_new_from_kernel),
                        DLSYM_ARG(aa_features_unref),
                        DLSYM_ARG(aa_policy_cache_dir_path_preview),
                        DLSYM_ARG(aa_policy_cache_new),
                        DLSYM_ARG(aa_policy_cache_replace_all),
                        DLSYM_ARG(aa_policy_cache_unref));
}
#endif

bool mac_apparmor_use(void) {
        static int cached_use = -1;

        if (cached_use < 0) {
                _cleanup_free_ char *p = NULL;

                cached_use =
                        read_one_line_file("/sys/module/apparmor/parameters/enabled", &p) >= 0 &&
                        parse_boolean(p) > 0;
        }

        return cached_use;
}
