/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dlfcn.h>
#include <link.h>
#include <string.h>

/* This macro will turn off invocation of elf_build_id_get() by the log.c logging macros, so that we don't
 * end up in a loop where we want to log, and the log function macros want to call us. */
#define LOG_BUILD_ID_SUPPRESS

#include "elf-metadata.h"
#include "log.h"
#include "macro.h"

static thread_local struct {
        const char *func;
        elf_build_id build_id;
} cache = {};

const elf_build_id* elf_build_id_get(const char *func) {
        struct link_map *m;
        ElfW(Ehdr) *h;
        Dl_info info;

        /* This returns a static const structure referencing the build ID of the calling function. The return
         * structure and the data its fields point to are valid as long as the relevant ELF module remains
         * loaded. */

        if (func && cache.func == func) {
                /* We do some really basic caching: the caller is supposed to pass __func__ as argument, and
                 * as long as that pointer doesn't change we'll return the same cached build ID. Note that we
                 * compare by pointer here (!) since __func__ is defined to resolve to a static const char
                 * array, and hence it's address should suffice for identifying whether we are still in the
                 * same function. */

                if (cache.build_id.size == 0) /* couldn't resolve (or in other words: we do negative caching too) */
                        return NULL;

                return &cache.build_id;
        }

        /* Look at the caller's address, and find the ELF module for it */
        if (dladdr1(__builtin_return_address(0), &info, (void**) &m, RTLD_DL_LINKMAP) == 0) {
                log_debug("Failed to resolve calling address with dladdr1(): %m");
                goto fail;
        }

        /* This should be an ELF object */
        h = (ElfW(Ehdr)*) info.dli_fbase;
        if (!h ||
            h->e_ident[0] != 0x7f ||
            h->e_ident[1] != 'E' ||
            h->e_ident[2] != 'L' ||
            h->e_ident[3] != 'F') {
                log_debug("Discovered object does not point to ELF header, ignoring.");
                goto fail;
        }

        /* Let's iterate through all sections of this ELF object, and look for the PT_NOTE ones */
        for (size_t i = 0; i < h->e_phnum; i++) {
                ElfW(Phdr) *p;
                ElfW(Nhdr) *n;
                size_t left;

                p = (ElfW(Phdr)*) ((uint8_t*) info.dli_fbase + h->e_phoff + (i * h->e_phentsize));
                if (p->p_type != PT_NOTE)
                        continue;

                /* We found a PT_NOTE section, yay! */
                n = (ElfW(Nhdr)*) ((uint8_t*) m->l_addr + p->p_vaddr);
                left = (size_t) p->p_memsz;

                /* Let's now look for a NT_GNU_BUILD_ID section with name "GNU" */
                while (left > 0) {
                        size_t sz;

                        if (left < sizeof(ElfW(Nhdr))) {
                                log_debug("Truncated note header, ignoring.");
                                goto fail;
                        }

                        if (n->n_type == NT_GNU_BUILD_ID &&
                            n->n_namesz == 4 &&
                            memcmp((char*) n + sizeof(ElfW(Nhdr)), "GNU", 4) == 0) {

                                /* Yippieh, found the build ID */

                                if (n->n_descsz == 0) {
                                        log_debug("Found zero-length GNU build ID, ignoring.");
                                        goto fail;
                                }

                                cache.func = func;
                                cache.build_id = (elf_build_id) {
                                        .fname = info.dli_fname,
                                        .id = (const uint8_t*) n + sizeof(ElfW(Nhdr)) + 4,
                                        .size = n->n_descsz,
                                };

                                return &cache.build_id;
                        }

                        sz = sizeof(ElfW(Nhdr)) + ALIGN4(n->n_namesz) + ALIGN4(n->n_descsz);
                        n = (ElfW(Nhdr*)) ((uint8_t*) n + sz);
                        left -= sz;
                }
        }

        /* No note found */

fail:
        cache.func = func;
        cache.build_id = (elf_build_id) {};
        return NULL;
}
