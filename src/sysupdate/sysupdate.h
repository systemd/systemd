/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "specifier.h"
#include "sysupdate-forward.h"

typedef struct Context {
        char *component;

        Transfer **transfers;
        size_t n_transfers;

        Transfer **disabled_transfers;
        size_t n_disabled_transfers;

        Hashmap *features; /* Defined features, keyed by ID */

        UpdateSet **update_sets;
        size_t n_update_sets;

        UpdateSet *newest_installed, *candidate;

        Hashmap *web_cache; /* Cache for downloaded resources, keyed by URL */

        int installdb_fd;
} Context;

Context* context_free(Context *c);
DEFINE_TRIVIAL_CLEANUP_FUNC(Context*, context_free);

extern bool arg_sync;
extern uint64_t arg_instances_max;
extern char *arg_root;
extern char *arg_transfer_source;

extern const Specifier specifier_table[];
