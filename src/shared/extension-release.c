/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "architecture.h"
#include "env-util.h"
#include "extension-release.h"
#include "log.h"
#include "os-util.h"
#include "strv.h"

int extension_release_validate(
                const char *name,
                const char *host_os_release_id,
                const char *host_os_release_version_id,
                const char *host_os_release_sysext_level,
                const char *host_sysext_scope,
                char **extension_release) {

        const char *extension_release_id = NULL, *extension_release_sysext_level = NULL, *extension_architecture = NULL;

        assert(name);
        assert(!isempty(host_os_release_id));

        /* Now that we can look into the extension image, let's see if the OS version is compatible */
        if (strv_isempty(extension_release)) {
                log_debug("Extension '%s' carries no extension-release data, ignoring extension.", name);
                return 0;
        }

        if (host_sysext_scope) {
                _cleanup_strv_free_ char **extension_sysext_scope_list = NULL;
                const char *extension_sysext_scope;
                bool valid;

                extension_sysext_scope = strv_env_pairs_get(extension_release, "SYSEXT_SCOPE");
                if (extension_sysext_scope) {
                        extension_sysext_scope_list = strv_split(extension_sysext_scope, WHITESPACE);
                        if (!extension_sysext_scope_list)
                                return -ENOMEM;
                }

                /* by default extension are good for attachment in portable service and on the system */
                valid = strv_contains(
                                extension_sysext_scope_list ?: STRV_MAKE("system", "portable"),
                                host_sysext_scope);
                if (!valid) {
                        log_debug("Extension '%s' is not suitable for scope %s, ignoring extension.", name, host_sysext_scope);
                        return 0;
                }
        }

        /* When the architecture field is present and not '_any' it must match the host - for now just look at uname but in
         * the future we could check if the kernel also supports 32 bit or binfmt has a translator set up for the architecture */
        extension_architecture = strv_env_pairs_get(extension_release, "ARCHITECTURE");
        if (!isempty(extension_architecture) && !streq(extension_architecture, "_any") &&
            !streq(architecture_to_string(uname_architecture()), extension_architecture)) {
                log_debug("Extension '%s' is for architecture '%s', but deployed on top of '%s'.",
                          name, extension_architecture, architecture_to_string(uname_architecture()));
                return 0;
        }

        extension_release_id = strv_env_pairs_get(extension_release, "ID");
        if (isempty(extension_release_id)) {
                log_debug("Extension '%s' does not contain ID in extension-release but requested to match '%s' or be '_any'",
                          name, host_os_release_id);
                return 0;
        }

        /* A sysext with no host OS dependency (static binaries or scripts) can match
         * '_any' host OS, and VERSION_ID or SYSEXT_LEVEL are not required anywhere */
        if (streq(extension_release_id, "_any")) {
                log_debug("Extension '%s' matches '_any' OS.", name);
                return 1;
        }

        if (!streq(host_os_release_id, extension_release_id)) {
                log_debug("Extension '%s' is for OS '%s', but deployed on top of '%s'.",
                          name, extension_release_id, host_os_release_id);
                return 0;
        }

        /* Rolling releases do not typically set VERSION_ID (eg: ArchLinux) */
        if (isempty(host_os_release_version_id) && isempty(host_os_release_sysext_level)) {
                log_debug("No version info on the host (rolling release?), but ID in %s matched.", name);
                return 1;
        }

        /* If the extension has a sysext API level declared, then it must match the host API
         * level. Otherwise, compare OS version as a whole */
        extension_release_sysext_level = strv_env_pairs_get(extension_release, "SYSEXT_LEVEL");
        if (!isempty(host_os_release_sysext_level) && !isempty(extension_release_sysext_level)) {
                if (!streq_ptr(host_os_release_sysext_level, extension_release_sysext_level)) {
                        log_debug("Extension '%s' is for sysext API level '%s', but running on sysext API level '%s'",
                                  name, strna(extension_release_sysext_level), strna(host_os_release_sysext_level));
                        return 0;
                }
        } else if (!isempty(host_os_release_version_id)) {
                const char *extension_release_version_id;

                extension_release_version_id = strv_env_pairs_get(extension_release, "VERSION_ID");
                if (isempty(extension_release_version_id)) {
                        log_debug("Extension '%s' does not contain VERSION_ID in extension-release but requested to match '%s'",
                                  name, strna(host_os_release_version_id));
                        return 0;
                }

                if (!streq_ptr(host_os_release_version_id, extension_release_version_id)) {
                        log_debug("Extension '%s' is for OS '%s', but deployed on top of '%s'.",
                                  name, strna(extension_release_version_id), strna(host_os_release_version_id));
                        return 0;
                }
        } else if (isempty(host_os_release_version_id) && isempty(host_os_release_sysext_level)) {
                /* Rolling releases do not typically set VERSION_ID (eg: ArchLinux) */
                log_debug("No version info on the host (rolling release?), but ID in %s matched.", name);
                return 1;
        }

        log_debug("Version info of extension '%s' matches host.", name);
        return 1;
}

int parse_env_extension_hierarchies(char ***ret_hierarchies) {
        _cleanup_free_ char **l = NULL;
        int r;

        r = getenv_path_list("SYSTEMD_SYSEXT_HIERARCHIES", &l);
        if (r == -ENXIO) {
                /* Default when unset */
                l = strv_new("/usr", "/opt");
                if (!l)
                        return -ENOMEM;
        } else if (r < 0)
                return r;

        *ret_hierarchies = TAKE_PTR(l);
        return 0;
}
