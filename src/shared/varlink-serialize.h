/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cleanup-util.h"
#include "forward.h"

typedef struct VarlinkDeserialize VarlinkDeserialize;

VarlinkDeserialize* varlink_deserialize_free(VarlinkDeserialize *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(VarlinkDeserialize*, varlink_deserialize_free);

int varlink_get_socket_cookie(sd_varlink *v, uint64_t *ret);
sd_varlink* varlink_server_get_connection(sd_varlink_server *s, uint64_t cookie);
int varlink_serialize(sd_varlink *v, FILE *f, FDSet *fds);
/* Pass fields with the "varlink-connection-" prefix stripped. The cookie starts a record and the socket fd
 * completes it. Returns positive on completion. A NULL server skips restoration, optionally returning the cookie. */
int varlink_deserialize_one(sd_varlink_server *s, const char *value, FDSet *fds, VarlinkDeserialize **state, uint64_t *ret_cookie);

int varlink_server_serialize(sd_varlink_server *s, const char *name, FILE *f, FDSet *fds);
int varlink_server_deserialize_one(sd_varlink_server *s, const char *value, FDSet *fds);

bool varlink_server_contains_socket(sd_varlink_server *s, const char *address);
