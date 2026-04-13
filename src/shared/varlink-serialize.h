/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int varlink_server_serialize(sd_varlink_server *s, const char *name, FILE *f, FDSet *fds);
int varlink_server_deserialize_one(sd_varlink_server *s, const char *value, FDSet *fds);

bool varlink_server_contains_socket(sd_varlink_server *s, const char *address);
