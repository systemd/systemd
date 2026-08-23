/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

#define LUO_SESSION_NAME "systemd"

/* Index (token) 0 in the LUO session is always the mapping memfd, which contains a versioned JSON document
 * with manager-level state and a "units" object mapping unit ids to per-unit objects with an "fdstore" array
 * of fd store entries:
 *
 *   {
 *     "version": 1,
 *     "state": { },
 *     "units": {
 *       "unit-name.service": {
 *         "fdstore": [
 *           { "type": "fd",          "name": "fdname1", "token": 1 },
 *           { "type": "luo_session", "name": "fdname3", "sessionName": "unit.service/myapp" }
 *         ]
 *       }
 *     }
 *   }
 *
 * type=fd:          the fd was preserved in the "systemd" LUO session with the given token.
 * type=luo_session: a service-owned LUO session that survives kexec independently,
 *                   retrieved by session_name on the next boot.
 */
#define LUO_MAPPING_INDEX UINT64_C(0)
#define LUO_PROTOCOL_VERSION UINT64_C(1)

int luo_open_device(void);
int luo_create_session(int device_fd, const char *name);
int luo_retrieve_session(int device_fd, const char *name);
int luo_session_preserve_fd(int session_fd, int fd, uint64_t token);
int luo_session_retrieve_fd(int session_fd, uint64_t token);
int luo_session_finish(int session_fd);

bool luo_session_name_is_valid(const char *name);

int luo_parse_serialization(sd_json_variant **ret, int **ret_fds, size_t *ret_n_fds);
int luo_serialization_add_shutdown_timestamps(sd_json_variant **serialization, const dual_timestamp *shutdown_late_start, const dual_timestamp *shutdown_late_finish);
int luo_preserve_fd_stores(sd_json_variant *serialization, int *ret_session_fd);

int fd_is_luo_session(int fd);
int fd_get_luo_session_name(int fd, char **ret);
