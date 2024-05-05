/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dlfcn.h>

#include "macro.h"

static inline void* safe_dlclose(void *dl) {
        if (!dl)
                return NULL;

        assert_se(dlclose(dl) == 0);
        return NULL;
}

static inline void dlclosep(void **dlp) {
        safe_dlclose(*dlp);
}

int dlsym_many_or_warn_sentinel(void *dl, int log_level, ...) _sentinel_;
int dlopen_many_sym_or_warn_sentinel(void **dlp, const char *filename, int log_level, ...) _sentinel_;

#define dlsym_many_or_warn(dl, log_level, ...) \
        dlsym_many_or_warn_sentinel(dl, log_level, __VA_ARGS__, NULL)
#define dlopen_many_sym_or_warn(dlp, filename, log_level, ...) \
        dlopen_many_sym_or_warn_sentinel(dlp, filename, log_level, __VA_ARGS__, NULL)

#define DLSYM_PROTOTYPE(symbol)                 \
        extern typeof(symbol)* sym_##symbol
#define DLSYM_FUNCTION(symbol)                  \
        typeof(symbol)* sym_##symbol = NULL

/* Macro useful for putting together variable/symbol name pairs when calling dlsym_many_or_warn(). Assumes
 * that each library symbol to resolve will be placed in a variable with the "sym_" prefix, i.e. a symbol
 * "foobar" is loaded into a variable "sym_foobar". */
#define DLSYM_ARG(arg) \
        ({ assert_cc(__builtin_types_compatible_p(typeof(sym_##arg), typeof(&arg))); &sym_##arg; }), STRINGIFY(arg)

/* libbpf is a bit confused about type-safety and API compatibility. Provide a macro that can tape over that mess. Sad. */
#define DLSYM_ARG_FORCE(arg) \
        &sym_##arg, STRINGIFY(arg)

#define ELF_NOTE_DLOPEN_VENDOR "FDO"
#define ELF_NOTE_DLOPEN_TYPE 0x407c0c0a

/* Add an ".note.dlopen" ELF note to our binary that declares our weak dlopen() dependency. This
 * information can be read from an ELF file via "readelf -p .note.dlopen" or an equivalent command. */
#define _ELF_NOTE_DLOPEN(module, variable_name)                         \
        __attribute__((used, section(".note.dlopen"))) _Alignas(sizeof(uint32_t)) static const struct { \
                struct {                                                \
                        uint32_t n_namesz, n_descsz, n_type;            \
                } nhdr;                                                 \
                char name[sizeof(ELF_NOTE_DLOPEN_VENDOR)];              \
                _Alignas(sizeof(uint32_t)) char dlopen_module[sizeof(module)]; \
        } variable_name = {                                             \
                .nhdr = {                                               \
                        .n_namesz = sizeof(ELF_NOTE_DLOPEN_VENDOR),     \
                        .n_descsz = sizeof(module),                     \
                        .n_type   = ELF_NOTE_DLOPEN_TYPE,               \
                },                                                      \
                .name = ELF_NOTE_DLOPEN_VENDOR,                         \
                .dlopen_module = module,                                \
        }

/* The 'priority' must be one of 'required', 'recommended' or 'suggested' as per specification */
#define ELF_NOTE_DLOPEN(module, feature, description, priority) \
        _ELF_NOTE_DLOPEN("{\"soname\":\"" module "\",\"feature\":\"" feature "\",\"description\":\"" description "\",\"priority\":\"" priority "\"}", UNIQ_T(s, UNIQ))
