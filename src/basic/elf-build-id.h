/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdint.h>

typedef struct build_id_ref build_id_ref;

#include "macro.h"

/* Define a generic placeholder type for the GNU build ID ELF note. We could define this via the ELF types
 * from link.h, but we don't want to pull that into all our source files, hence abstract this away here, via
 * this empty placeholder type. */
struct build_id_ref {
        uint8_t _[0];
};

/* A linker script ensures this symbols always references the GNU ELF note section of the current ELF executable. */
_weak_   /* → Handle gracefully if the symbol cannot be resolved */
_hidden_ /* → Disable interposition of this symbol, i.e. we never want to resolve this in the GOT, but only locally in this ELF object */
extern const build_id_ref _elf_note_build_id[];

const uint8_t *read_build_id(const build_id_ref *ref, size_t *ret_size);

/* Enough space for a 256bit hash, formatted in hex (in reality 160bit SHA1 seems to be the most people use,
 * so this should be ample space) */
#define BUILD_ID_STRING_MAX (256U/4U+1U)
const char *read_build_id_string_internal(const build_id_ref *ref, char buf[static BUILD_ID_STRING_MAX]);
#define read_build_id_string(id) read_build_id_string_internal(id, (char[BUILD_ID_STRING_MAX]) {})
