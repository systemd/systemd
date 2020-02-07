/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <pwd.h>
#include <shadow.h>

#include "user-record.h"

/* Synthesizes a UserRecord object from NSS data */

int nss_passwd_to_user_record(const struct passwd *pwd, const struct spwd *spwd, UserRecord **ret);
int nss_spwd_for_passwd(const struct passwd *pwd, struct spwd *ret_spwd, char **ret_buffer);

int nss_user_record_by_name(const char *name, UserRecord **ret);
int nss_user_record_by_uid(uid_t uid, UserRecord **ret);
