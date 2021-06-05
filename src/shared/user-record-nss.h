/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <grp.h>
#include <gshadow.h>
#include <pwd.h>
#include <shadow.h>

#include "group-record.h"
#include "user-record.h"

/* Synthesize UserRecord and GroupRecord objects from NSS data */

int nss_passwd_to_user_record(const struct passwd *pwd, const struct spwd *spwd, UserRecord **ret);
int nss_spwd_for_passwd(const struct passwd *pwd, struct spwd *ret_spwd, char **ret_buffer);

int nss_user_record_by_name(const char *name, bool with_shadow, UserRecord **ret);
int nss_user_record_by_uid(uid_t uid, bool with_shadow, UserRecord **ret);

int nss_group_to_group_record(const struct group *grp, const struct sgrp *sgrp, GroupRecord **ret);
int nss_sgrp_for_group(const struct group *grp, struct sgrp *ret_sgrp, char **ret_buffer);

int nss_group_record_by_name(const char *name, bool with_shadow, GroupRecord **ret);
int nss_group_record_by_gid(gid_t gid, bool with_shadow, GroupRecord **ret);
