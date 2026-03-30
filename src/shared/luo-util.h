/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"
#include "sd-forward.h"

#define LUO_SESSION_NAME "systemd"

/* Index (token) 0 in the LUO session is always the mapping memfd, which contains a JSON document mapping
 * unit ids to arrays of fd store entries:
 *
 *   {
 *     "unit-name.service": [
 *       { "type": "fd",          "name": "fdname1", "token": 1 },
 *       { "type": "fd",          "name": "fdname2", "token": 2 },
 *     ],
 *     "other-unit.service": [
 *       { "type": "fd",          "name": "stored", "token": 3 }
 *     ]
 *   }
 *
 * type=fd:          the fd was preserved in the "systemd" LUO session with the given token.
 */
#define LUO_MAPPING_INDEX UINT64_C(0)

int luo_open_device(void);
int luo_create_session(int device_fd, const char *name);
int luo_retrieve_session(int device_fd, const char *name);
int luo_session_preserve_fd(int session_fd, int fd, uint64_t token);
int luo_session_retrieve_fd(int session_fd, uint64_t token);
int luo_session_finish(int session_fd);

int luo_parse_serialization(sd_json_variant **ret, int **ret_fds, size_t *ret_n_fds);
int luo_preserve_fd_stores(sd_json_variant *serialization, int *ret_session_fd);
