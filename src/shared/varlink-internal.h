/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

#include "fdset.h"
#include "varlink.h"

int varlink_server_serialize(VarlinkServer *s, FILE *f, FDSet *fds);
int varlink_server_deserialize_one(VarlinkServer *s, const char *value, FDSet *fds);
