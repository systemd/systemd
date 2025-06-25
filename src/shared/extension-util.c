/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "architecture.h"
#include "chase.h"
#include "env-util.h"
#include "extension-util.h"
#include "log.h"
#include "os-util.h"
#include "string-util.h"
#include "strv.h"

int extension_release_validate(
                const char *name,
                const char *host_os_release_id,
                const char *host_os_release_id_like,
                const char *host_os_release_version_id,
                const char *host_os_extension_release_level,
                const char *host_extension_scope,
                char **extension_release,
                ImageClass image_class) {

        const char *extension_release_id = NULL, *extension_release_level = NULL, *extension_architecture = NULL;
        const char *extension_level = image_class == IMAGE_CONFEXT ? "CONFEXT_LEVEL" : "SYSEXT_LEVEL";
        const char *extension_scope = image_class == IMAGE_CONFEXT ? "CONFEXT_SCOPE" : "SYSEXT_SCOPE";
        _cleanup_strv_free_ char **id_like_l = NULL;

        assert(name);
        assert(!isempty(host_os_release_id));

        /* Now that we can look into the extension/confext image, let's see if the OS version is compatible */
        if (strv_isempty(extension_release)) {
                log_debug("Extension '%s' carries no release data, ignoring.", name);
                return 0;
        }

        if (host_extension_scope) {
                _cleanup_strv_free_ char **scope_list = NULL;
                const char *scope;
                bool valid;

                scope = strv_env_pairs_get(extension_release, extension_scope);
                if (scope) {
                        scope_list = strv_split(scope, WHITESPACE);
                        if (!scope_list)
                                return -ENOMEM;
                }

                /* By default extension are good for attachment in portable service and on the system */
                valid = strv_contains(
                        scope_list ?: STRV_MAKE("system", "portable"),
                        host_extension_scope);
                if (!valid) {
                        log_debug("Extension '%s' is not suitable for scope %s, ignoring.", name, host_extension_scope);
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
                log_debug("Extension '%s' does not contain ID in release file but requested to match '%s' or be '_any'",
                        name, host_os_release_id);
                return 0;
        }

        /* A sysext(or confext) with no host OS dependency (static binaries or scripts) can match
         * '_any' host OS, and VERSION_ID or SYSEXT_LEVEL(or CONFEXT_LEVEL) are not required anywhere */
        if (streq(extension_release_id, "_any")) {
                log_debug("Extension '%s' matches '_any' OS.", name);
                return 1;
        }

        /* Match extension OS ID against host OS ID or ID_LIKE */
        if (host_os_release_id_like) {
                id_like_l = strv_split(host_os_release_id_like, WHITESPACE);
                if (!id_like_l)
                        return log_oom();
        }

        if (!streq(host_os_release_id, extension_release_id) && !strv_contains(id_like_l, extension_release_id)) {
                log_debug("Extension '%s' is for OS '%s', but deployed on top of '%s'%s%s%s.",
                          name, extension_release_id, host_os_release_id,
                          host_os_release_id_like ? " (like '" : "",
                          strempty(host_os_release_id_like),
                          host_os_release_id_like ? "')" : "");
                return 0;
        }

        /* Rolling releases do not typically set VERSION_ID (eg: ArchLinux) */
        if (isempty(host_os_release_version_id) && isempty(host_os_extension_release_level)) {
                log_debug("No version info on the host (rolling release?), but ID in %s matched.", name);
                return 1;
        }

        /* If the extension has a sysext API level declared, then it must match the host API
         * level. Otherwise, compare OS version as a whole */
        extension_release_level = strv_env_pairs_get(extension_release, extension_level);
        if (!isempty(host_os_extension_release_level) && !isempty(extension_release_level)) {
                if (!streq_ptr(host_os_extension_release_level, extension_release_level)) {
                        log_debug("Extension '%s' is for API level '%s', but running on API level '%s'",
                                name, strna(extension_release_level), strna(host_os_extension_release_level));
                        return 0;
                }
        } else if (!isempty(host_os_release_version_id)) {
                const char *extension_release_version_id;

                extension_release_version_id = strv_env_pairs_get(extension_release, "VERSION_ID");
                if (isempty(extension_release_version_id)) {
                        log_debug("Extension '%s' does not contain VERSION_ID in release file but requested to match '%s'",
                                  name, strna(host_os_release_version_id));
                        return 0;
                }

                if (!streq_ptr(host_os_release_version_id, extension_release_version_id)) {
                        log_debug("Extension '%s' is for OS '%s', but deployed on top of '%s'.",
                                  name, strna(extension_release_version_id), strna(host_os_release_version_id));
                        return 0;
                }
        } else if (isempty(host_os_release_version_id) && isempty(host_os_extension_release_level)) {
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
                else if (streq(hierarchy_env, "SYSTEMD_SYSEXT_AND_CONFEXT_HIERARCHIES"))
                        /* Combined sysext and confext directories */
                        l = strv_new("/usr", "/opt", "/etc");
                else
                        return -ENXIO;
        } else if (r < 0)
                return r;

        *ret_hierarchies = TAKE_PTR(l);
        return 0;
}

int extension_has_forbidden_content(const char *root) {
        int r;

        /* Insist that extension images do not overwrite the underlying OS release file (it's fine if
         * they place one in /etc/os-release, i.e. where things don't matter, as they aren't
         * merged.) */
        r = chase("/usr/lib/os-release", root, CHASE_PREFIX_ROOT, NULL, NULL);
        if (r > 0) {
                log_debug("Extension contains '/usr/lib/os-release', which is not allowed, refusing.");
                return 1;
        }
        if (r < 0 && r != -ENOENT)
                return log_debug_errno(r, "Failed to determine whether '/usr/lib/os-release' exists in the extension: %m");

        return 0;
}
