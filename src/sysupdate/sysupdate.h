/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "specifier.h"

/* Forward declare this type so that Transfers can point at it */
typedef struct Context Context;

extern bool arg_sync;
extern uint64_t arg_instances_max;
extern char *arg_root;
extern char *arg_transfer_source;

extern const Specifier specifier_table[];
