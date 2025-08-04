/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "apparmor-setup.h"
#include "apparmor-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "string-util.h"
#include "strv.h"

int mac_apparmor_setup(void) {
#if HAVE_APPARMOR
        _cleanup_(sym_aa_policy_cache_unrefp) aa_policy_cache *policy_cache = NULL;
        _cleanup_(sym_aa_features_unrefp) aa_features *features = NULL;
        _cleanup_free_ char *current_profile = NULL, *cache_dir_path = NULL;
        int r;

        if (!mac_apparmor_use()) {
                log_debug("Skipping AppArmor initialization: not supported by the kernel or disabled.");
                return 0;
        }

        r = dlopen_libapparmor();
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to load libapparmor: %m");

        /* To honor LSM stacking, check per-LSM subdirectory first, and then the generic one as fallback. */
        FOREACH_STRING(current_file, "/proc/self/attr/apparmor/current", "/proc/self/attr/current") {
                r = read_one_line_file(current_file, &current_profile);
                if (r >= 0)
                        break;
                if (r != -ENOENT)
                        log_warning_errno(r, "Failed to read current AppArmor profile from '%s', ignoring: %m",
                                          current_file);
        }
        if (!current_profile) {
                log_warning("Failed to get the current AppArmor profile of our own process, ignoring.");
                return 0;
        }
        if (!streq(current_profile, "unconfined")) {
                log_debug("We are already confined in an AppArmor profile.");
                return 0;
        }

        r = sym_aa_features_new_from_kernel(&features);
        if (r < 0) {
                log_warning_errno(errno, "Failed to get the AppArmor feature set from the kernel, ignoring: %m");
                return 0;
        }

        cache_dir_path = sym_aa_policy_cache_dir_path_preview(features, AT_FDCWD, "/etc/apparmor/earlypolicy");
        if (!cache_dir_path) {
                log_debug_errno(errno, "Failed to get the path of the early AppArmor policy cache directory, ignoring: %m");
                return 0;
        }

        /* aa_policy_cache_new will internally use the same path as aa_policy_cache_dir_path_preview has returned. */
        r = sym_aa_policy_cache_new(&policy_cache, features, AT_FDCWD, "/etc/apparmor/earlypolicy", 0);
        if (r < 0) {
                if (errno == ENOENT)
                        log_debug_errno(errno,
                                        "The early AppArmor policy cache directory '%s' does not exist.",
                                        cache_dir_path);
                else
                        log_warning_errno(errno, "Failed to create a new AppArmor policy cache, ignoring: %m");
                return 0;
        }

        r = sym_aa_policy_cache_replace_all(policy_cache, NULL);
        if (r < 0) {
                log_warning_errno(errno,
                                  "Failed to load the profiles from the early AppArmor policy cache directory '%s', ignoring: %m",
                                  cache_dir_path);
                return 0;
        }

        log_info("Successfully loaded all binary profiles from AppArmor early policy cache (%s).", cache_dir_path);

        r = sym_aa_change_profile("systemd");
        if (r < 0) {
                if (errno == ENOENT)
                        log_debug_errno(errno,
                                        "Failed to change to AppArmor profile 'systemd'.\n"
                                        "Please ensure that one of the binary profile files in policy cache directory '%s' contains a profile with that name.",
                                        cache_dir_path);
                else
                        log_error_errno(errno, "Failed to change to AppArmor profile 'systemd': %m");
                return 0;
        }

        log_info("Changed to AppArmor profile systemd.");
#endif
        return 0;
}
