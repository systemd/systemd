/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int varlink_server_serialize(sd_varlink_server *s, const char *name, FILE *f, FDSet *fds);
int varlink_server_deserialize_one(sd_varlink_server *s, const char *value, FDSet *fds);

int varlink_server_serialize_connections(sd_varlink_server *s, const char *key, FILE *f, FDSet *fds);
int varlink_server_deserialize_connections(sd_varlink_server *s, const char *value, FDSet *fds);
int varlink_serialize_connection_id(sd_varlink *link, const char *key, FILE *f);

bool varlink_server_contains_socket(sd_varlink_server *s, const char *address);
