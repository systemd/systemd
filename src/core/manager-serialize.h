/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "manager.h"
#include "fdset.h"

#define DESTROY_IPC_FLAG (UINT32_C(1) << 31)

int manager_open_serialization(Manager *m, FILE **ret_f);
int manager_serialize(Manager *m, FILE *f, FDSet *fds, bool switching_root);
int manager_deserialize(Manager *m, FILE *f, FDSet *fds);
