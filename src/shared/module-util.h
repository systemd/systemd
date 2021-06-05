/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <libkmod.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(struct kmod_ctx*, kmod_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct kmod_module*, kmod_module_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct kmod_list*, kmod_module_unref_list, NULL);

int module_load_and_warn(struct kmod_ctx *ctx, const char *module, bool verbose);
