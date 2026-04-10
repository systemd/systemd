/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "specifier.h"
#include "sysupdate-forward.h"

extern bool arg_sync;
extern uint64_t arg_instances_max;
extern char *arg_root;
extern char *arg_transfer_source;

extern const Specifier specifier_table[];

const char* context_get_cached_ddi_path(Context *c, const char *key);
/* Takes ownership of path on success. */
int context_put_cached_ddi_path(Context *c, const char *key, char *path);
