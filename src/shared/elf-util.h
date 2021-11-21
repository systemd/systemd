/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"

#if HAVE_ELFUTILS
/* Parse an ELF object in a forked process, so that errors while iterating over
 * untrusted and potentially malicious data do not propagate to the main caller's process. */
int parse_elf_object(int fd, const char *executable, char **ret, JsonVariant **ret_package_metadata);
#else
static inline int parse_elf_object(int fd, const char *executable, char **ret, JsonVariant **ret_package_metadata) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "elfutils disabled, parsing ELF objects not supported");
}
#endif
