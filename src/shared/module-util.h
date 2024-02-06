/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dlfcn-util.h"

#if HAVE_KMOD

#include <libkmod.h>

#include "macro.h"

DLSYM_PROTOTYPE(kmod_list_next);
DLSYM_PROTOTYPE(kmod_load_resources);
DLSYM_PROTOTYPE(kmod_module_get_initstate);
DLSYM_PROTOTYPE(kmod_module_get_module);
DLSYM_PROTOTYPE(kmod_module_get_name);
DLSYM_PROTOTYPE(kmod_module_new_from_lookup);
DLSYM_PROTOTYPE(kmod_module_probe_insert_module);
DLSYM_PROTOTYPE(kmod_module_unref);
DLSYM_PROTOTYPE(kmod_module_unref_list);
DLSYM_PROTOTYPE(kmod_new);
DLSYM_PROTOTYPE(kmod_set_log_fn);
DLSYM_PROTOTYPE(kmod_unref);
DLSYM_PROTOTYPE(kmod_validate_resources);

int dlopen_libkmod(void);

DEFINE_TRIVIAL_CLEANUP_FUNC(struct kmod_ctx*, sym_kmod_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct kmod_module*, sym_kmod_module_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct kmod_list*, sym_kmod_module_unref_list, NULL);

#define sym_kmod_list_foreach(list_entry, first_entry) \
        for (list_entry = first_entry; \
                list_entry != NULL; \
                list_entry = sym_kmod_list_next(first_entry, list_entry))

int module_load_and_warn(struct kmod_ctx *ctx, const char *module, bool verbose);
int module_setup_context(struct kmod_ctx **ret);

#else

struct kmod_ctx;

static inline int dlopen_libkmod(void) {
        return -EOPNOTSUPP;
}

static inline int module_setup_context(struct kmod_ctx **ret) {
        return -EOPNOTSUPP;
}

static inline int module_load_and_warn(struct kmod_ctx *ctx, const char *module, bool verbose) {
        return -EOPNOTSUPP;
}

#endif
