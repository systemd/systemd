/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright © 2017 Zbigniew Jędrzejewski-Szmek
***/

#include <libkmod.h>

#include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(struct kmod_ctx*, kmod_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct kmod_module*, kmod_module_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct kmod_list*, kmod_module_unref_list);
