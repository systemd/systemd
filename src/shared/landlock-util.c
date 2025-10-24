/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "landlock-util.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if HAVE_LANDLOCK_CONFIG
#include <landlockconfig.h>
#endif /* HAVE_LANDLOCK_CONFIG */

#include "fd-util.h"
#include "log.h"

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size, __u32 flags) {
        return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(int ruleset_fd, __u32 flags) {
        return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#if HAVE_LANDLOCK_CONFIG

static void *liblandlockconfig_dl = NULL;

DLSYM_PROTOTYPE(landlockconfig_parse_toml_directory) = NULL;
DLSYM_PROTOTYPE(landlockconfig_build_ruleset) = NULL;
DLSYM_PROTOTYPE(landlockconfig_free) = NULL;

int dlopen_landlockconfig(void) {
        ELF_NOTE_DLOPEN("landlockconfig",
                        "Support for Landlock configuration parsing",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "liblandlockconfig.so.0.1");

        return dlopen_many_sym_or_warn(
                        &liblandlockconfig_dl,
                        "liblandlockconfig.so.0.1",
                        LOG_DEBUG,
                        DLSYM_ARG(landlockconfig_parse_toml_directory),
                        DLSYM_ARG(landlockconfig_build_ruleset),
                        DLSYM_ARG(landlockconfig_free));
}

static bool is_landlock_available(void) {
        static int cached_abi = 0;

        if (cached_abi <= 0) {
                cached_abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
                if (cached_abi >= 1) {
                        log_debug("Landlock version %d is available", cached_abi);
                } else {
                        log_debug_errno(errno, "Landlock is not available: %m");
                }
        }

        return cached_abi > 0;
}

int landlock_apply(const char *path) {
        _cleanup_close_ int ruleset_fd = -EBADF;
        _cleanup_(sym_landlockconfig_freep) struct landlockconfig *config = NULL;
        int r;

        if (!path)
                return -EINVAL;

        if (!is_landlock_available()) {
                log_debug("Landlock is not available, skipping configuration from %s", path);
                return 0;
        }

        r = dlopen_landlockconfig();
        if (r < 0) {
                log_debug_errno(r, "Failed to load landlockconfig library, cannot apply configuration from %s: %m", path);
                return r;
        }

        config = sym_landlockconfig_parse_toml_directory(path, 0);
        if ((intptr_t)config <= 0)
                return log_debug_errno(-(intptr_t)config, "Failed to parse Landlock configuration from %s: %m", path);

        ruleset_fd = sym_landlockconfig_build_ruleset(config, 0);
        if (ruleset_fd < 0)
                return log_debug_errno(-ruleset_fd, "Failed to build Landlock ruleset: %m");

        r = landlock_restrict_self(ruleset_fd, 0);
        if (r < 0)
                return log_debug_errno(errno, "Failed to apply Landlock restrictions: %m");

        log_debug("Successfully applied Landlock configuration from %s", path);
        return 0;
}

#endif /* HAVE_LANDLOCK_CONFIG */
