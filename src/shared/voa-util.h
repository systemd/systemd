/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* The File Hierarchy for the Verification of OS Artifacts (VOA), see
 * https://uapi-group.org/specifications/specs/file_hierarchy_for_the_verification_of_os_artifacts/ */

typedef enum VoaMode {
        VOA_MODE_ARTIFACT_VERIFIER, /* $role/ */
        VOA_MODE_TRUST_ANCHOR,      /* trust-anchor-$role/ */
        _VOA_MODE_MAX,
        _VOA_MODE_INVALID = -EINVAL,
} VoaMode;

typedef enum VoaFlags {
        VOA_WARN = 1 << 0, /* Warn about entries the specification says to ignore, not just debug log */
} VoaFlags;

typedef struct VoaLookup {
        char **os;              /* OS identifiers, all of them are searched */
        const char *role;
        const char *context;    /* e.g. "default" */
        VoaMode mode;
        const char *technology;
        const char *suffix;     /* file name suffix, e.g. "-certificate.pem" */
} VoaLookup;

bool voa_identifier_is_valid(const char *s, bool allow_colon) _pure_;
bool voa_os_is_valid(const char *s) _pure_;

int voa_os_identifiers(int root_fd, char ***ret);
int voa_list_verifiers(
                int root_fd,
                const VoaLookup *lookup,
                VoaFlags flags,
                ConfFile ***ret_files,
                size_t *ret_n_files);
