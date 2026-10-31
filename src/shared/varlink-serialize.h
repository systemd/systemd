/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int varlink_get_socket_cookie(sd_varlink *v, uint64_t *ret);
sd_varlink* varlink_server_get_connection(sd_varlink_server *s, uint64_t cookie);
int varlink_serialize(sd_varlink *v, const char *key, FILE *f, FDSet *fds);
/* Pass a NULL server to skip a connection subsection during reload. */
int varlink_deserialize(sd_varlink_server *s, FILE *f, FDSet *fds);

int varlink_server_serialize(sd_varlink_server *s, const char *name, FILE *f, FDSet *fds);
int varlink_server_deserialize_one(sd_varlink_server *s, const char *value, FDSet *fds);

bool varlink_server_contains_socket(sd_varlink_server *s, const char *address);
