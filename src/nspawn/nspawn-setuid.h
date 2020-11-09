/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int change_uid_gid_raw(uid_t uid, gid_t gid, const gid_t *supplementary_gids, size_t n_supplementary_gids, bool chown_stdio);
int change_uid_gid(const char *user, bool chown_stdio, char **ret_home);
