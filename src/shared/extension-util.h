/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* Given an image name (for logging purposes), a set of os-release values from the host and a key-value pair
 * vector of extension-release variables, check that the distro and (system extension level or distro
 * version) match and return 1, and 0 otherwise. */
int extension_release_validate(
                const char *name,
                const char *host_os_release_id,
                const char *host_os_release_id_like,
                const char *host_os_release_version_id,
                const char *host_os_extension_release_level,
                const char *host_extension_scope,
                char **extension_release,
                ImageClass image_class);

/* Parse hierarchy variables and if not set, return "/usr /opt" for sysext and "/etc" for confext */
int parse_env_extension_hierarchies(char ***ret_hierarchies, const char *hierarchy_env);

/* Insist that extension images do not overwrite the underlying OS release file (it's fine if they place one
 * in /etc/os-release, i.e. where things don't matter, as they aren't merged.) */
int extension_has_forbidden_content(const char *root);
