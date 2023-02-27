/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Given an image name (for logging purposes), a set of os-release values from the host and a key-value pair
 * vector of extension-release/syscfg-releases variables, check that the distro and (system extension level
 * or distro version) match and return 1, and 0 otherwise. */
int extension_release_validate_internal(
                const char *name,
                const char *host_os_release_id,
                const char *host_os_release_version_id,
                const char *host_os_release_level,
                const char *host_scope,
                char **image_release_file,
                const char *syscfg_or_sysext_level,
                const char *syscfg_or_sysext_scope);

/* Parse hierarchy env variable and if not set, return default values */
int parse_env_extension_hierarchies(char ***ret_hierarchies, const char *hierarchy_env);
