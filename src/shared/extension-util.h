/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct HostProperties HostProperties;

/* Given an image name (for logging purposes), a set of os-release values from the host and a key-value pair
 * vector of extension-release variables, check that the distro and (system extension level or distro
 * version) match and return 1, and 0 otherwise. */
int extension_release_validate(
                const char *name,
                const char *host_os_release_id,
                const char *host_os_release_id_like,
                const char *host_os_release_version_id,
                const char *host_os_extension_release_level,
                const char *host_os_release_image_id,
                const char *host_os_release_image_version,
                const char *host_extension_scope,
                char **extension_release,
                ImageClass image_class);

/* Parse hierarchy variables and if not set, return "/usr /opt" for sysext and "/etc" for confext */
int parse_env_extension_hierarchies(char ***ret_hierarchies, const char *hierarchy_env);

/* Insist that extension images do not overwrite the underlying OS release file (it's fine if they place one
 * in /etc/os-release, i.e. where things don't matter, as they aren't merged.) */
int extension_has_forbidden_content(const char *root);

/* Find the backing device. Returns >0 on success, 0 if the volume is not an extension, and <0 on error. */
int extension_overlay_block(const char *p, ImageClass image_class, dev_t *ret);

/* Checks whether an extension image is suitable for the local system, based on the MATCH_HOSTNAME= and
 * related fields of its extension-release file, and the "user.uapi.match_…" extended attributes of the image
 * file or directory itself (see xattr-match.h, as set by systemd-sysupdate). The fields mirror the extended
 * attributes 1:1. Both are honoured. If both carry a rule for the same property, and the rules differ,
 * a warning is logged. The host properties are loaded lazily from the specified root directory (or the host
 * if NULL). Returns > 0 if the image is suitable, 0 if not (logged at debug level, or as warning if a rule
 * is invalid), < 0 on error. */
int extension_match_host(
                const char *name,
                const char *image_path,
                char **extension_release,
                HostProperties *host,
                const char *root);
