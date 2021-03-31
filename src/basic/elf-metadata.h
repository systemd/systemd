/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <sys/types.h>

/* Encapsulates a variable length ELF build ID. Usually SHA-1 (160bits) is used, but it could be any size */
typedef struct elf_build_id {
        const char *fname; /* ELF file name (i.e. path to main executable or .so) */
        const uint8_t *id;
        size_t size;
} elf_build_id;

const elf_build_id *elf_build_id_get(const char *func);
