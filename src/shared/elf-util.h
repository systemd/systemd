/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int dlopen_dw(int log_level);
int dlopen_elf(int log_level);

bool dlopen_dw_has_dwfl_set_sysroot(void);

/* Parse an ELF object in a forked process, so that errors while iterating over
 * untrusted and potentially malicious data do not propagate to the main caller's process.
 * If fork_disable_dump, the child process will not dump core if it crashes. */
int parse_elf_object(
                int fd,
                const char *executable,
                const char *root,
                bool fork_disable_dump,
                char **ret,
                sd_json_variant **ret_package_metadata,
                sd_json_variant **ret_dlopen_metadata);
