/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "architecture.h"
#include "env-util.h"
#include "extension-release.h"
#include "log.h"
#include "os-util.h"
#include "strv.h"

int release_file_validate(
                const char *name,
                const char *host_os_release_id,
                const char *host_os_release_version_id,
                const char *host_os_release_level,
                const char *host_scope,
                char **image_release_file,
                ImageClass image_class) {

        const char *confext_or_sysext_release_id = NULL, *release_confext_or_sysext_level = NULL, *confext_or_sysext_architecture = NULL;
        const char *confext_or_sysext_level = (image_class == IMAGE_CONFEXT) ? "CONFEXT_LEVEL" : "SYSEXT_LEVEL";
        const char *confext_or_sysext_scope = (image_class == IMAGE_CONFEXT) ? "CONFEXT_SCOPE" : "SYSEXT_SCOPE";

        assert(name);
        assert(!isempty(host_os_release_id));

        /* Now that we can look into the extension/confext image, let's see if the OS version is compatible */
        if (strv_isempty(image_release_file)) {
                log_debug("Extension '%s' carries no release data, ignoring.", name);
                return 0;
        }

        if (host_scope) {
                _cleanup_strv_free_ char **scope_list = NULL;
                const char *scope;
                bool valid;

                scope = strv_env_pairs_get(image_release_file, confext_or_sysext_scope);
                if (scope) {
                        scope_list = strv_split(scope, WHITESPACE);
                        if (!scope_list)
                                return -ENOMEM;
                }

                /* By default extension are good for attachment in portable service and on the system */
                valid = strv_contains(
                        scope_list ?: STRV_MAKE("system", "portable"),
                        host_scope);
                if (!valid) {
                        log_debug("Extension '%s' is not suitable for scope %s, ignoring.", name, host_scope);
                        return 0;
                }
        }

        /* When the architecture field is present and not '_any' it must match the host - for now just look at uname but in
         * the future we could check if the kernel also supports 32 bit or binfmt has a translator set up for the architecture */
        confext_or_sysext_architecture = strv_env_pairs_get(image_release_file, "ARCHITECTURE");
        if (!isempty(confext_or_sysext_architecture) && !streq(confext_or_sysext_architecture, "_any") &&
        !streq(architecture_to_string(uname_architecture()), confext_or_sysext_architecture)) {
                log_debug("Extension '%s' is for architecture '%s', but deployed on top of '%s'.",
                        name, confext_or_sysext_architecture, architecture_to_string(uname_architecture()));
                return 0;
        }

        confext_or_sysext_release_id = strv_env_pairs_get(image_release_file, "ID");
        if (isempty(confext_or_sysext_release_id)) {
                log_debug("Extension '%s' does not contain ID in release file but requested to match '%s' or be '_any'",
                        name, host_os_release_id);
                return 0;
        }

        /* A sysext(or confext) with no host OS dependency (static binaries or scripts) can match
         * '_any' host OS, and VERSION_ID or SYSEXT_LEVEL(or CONFEXT_LEVEL) are not required anywhere */
        if (streq(confext_or_sysext_release_id, "_any")) {
                log_debug("Extension '%s' matches '_any' OS.", name);
                return 1;
        }

        if (!streq(host_os_release_id, confext_or_sysext_release_id)) {
                log_debug("Extension '%s' is for OS '%s', but deployed on top of '%s'.",
                          name, confext_or_sysext_release_id, host_os_release_id);
                return 0;
        }

        /* Rolling releases do not typically set VERSION_ID (eg: ArchLinux) */
        if (isempty(host_os_release_version_id) && isempty(host_os_release_level)) {
                log_debug("No version info on the host (rolling release?), but ID in %s matched.", name);
                return 1;
        }

        /* If the extension has a sysext API level declared, then it must match the host API
         * level. Otherwise, compare OS version as a whole */
        release_confext_or_sysext_level = strv_env_pairs_get(image_release_file, confext_or_sysext_level);
        if (!isempty(host_os_release_level) && !isempty(release_confext_or_sysext_level)) {
                if (!streq_ptr(host_os_release_level, release_confext_or_sysext_level)) {
                        log_debug("Extension '%s' is for API level '%s', but running on API level '%s'",
                                name, strna(release_confext_or_sysext_level), strna(host_os_release_level));
                        return 0;
                }
        } else if (!isempty(host_os_release_version_id)) {
                const char *confext_or_extension_release_version_id;

                confext_or_extension_release_version_id = strv_env_pairs_get(image_release_file, "VERSION_ID");
                if (isempty(confext_or_extension_release_version_id)) {
                        log_debug("Extension '%s' does not contain VERSION_ID in release file but requested to match '%s'",
                                  name, strna(host_os_release_version_id));
                        return 0;
                }

                if (!streq_ptr(host_os_release_version_id, confext_or_extension_release_version_id)) {
                        log_debug("Extension '%s' is for OS '%s', but deployed on top of '%s'.",
                                  name, strna(confext_or_extension_release_version_id), strna(host_os_release_version_id));
                        return 0;
                }
        } else if (isempty(host_os_release_version_id) && isempty(host_os_release_level)) {
                /* Rolling releases do not typically set VERSION_ID (eg: ArchLinux) */
                log_debug("No version info on the host (rolling release?), but ID in %s matched.", name);
                return 1;
        }

        log_debug("Version info of extension '%s' matches host.", name);
        return 1;
}

int parse_env_extension_hierarchies(char ***ret_hierarchies, const char *hierarchy_env) {
        _cleanup_free_ char **l = NULL;
        int r;

        assert(hierarchy_env);
        r = getenv_path_list(hierarchy_env, &l);
        if (r == -ENXIO) {
                if (streq(hierarchy_env, "SYSTEMD_CONFEXT_HIERARCHIES"))
                        /* Default for confext when unset */
                        l = strv_new("/etc");
                else if (streq(hierarchy_env, "SYSTEMD_SYSEXT_HIERARCHIES"))
                        /* Default for sysext when unset */
                        l = strv_new("/usr", "/opt");
                else
                        return -ENXIO;
        } else if (r < 0)
                return r;

        *ret_hierarchies = TAKE_PTR(l);
        return 0;
}
