/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <link.h>
#include <sys/types.h>

#include "elf-build-id.h"
#include "hexdecoct.h"

const uint8_t *read_build_id(const build_id_ref *ref, size_t *ret_size) {
        const ElfW(Nhdr) *note;

        if (!ref)
                goto fail;

        note = (const ElfW(Nhdr)*) ref;
        if (note->n_type != NT_GNU_BUILD_ID)
                goto fail;
        if (note->n_namesz != 4)
                goto fail;

        if (memcmp((const char*) ref + sizeof(*note), "GNU", 4) != 0)
                goto fail;

        if (ret_size)
                *ret_size = note->n_descsz;

        return (const uint8_t*) ref + sizeof(*note) + 4;

fail:
        if (ret_size)
                *ret_size = 0;
        return NULL;
}

const char *read_build_id_string_internal(const build_id_ref *ref, char buf[static BUILD_ID_STRING_MAX]) {
        const uint8_t *raw;
        size_t sz;

        raw = read_build_id(ref, &sz);
        if (!raw)
                return NULL;

        if (sz*2+1 > BUILD_ID_STRING_MAX)
                return NULL;

        for (size_t i = 0; i < sz; i++) {
                buf[i*2] = hexchar(raw[i] >> 4);
                buf[i*2+1] = hexchar(raw[i] & 0xF);
        }
        buf[sz*2] = 0;

        return buf;
}
