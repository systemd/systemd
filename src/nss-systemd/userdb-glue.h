/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <nss.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

#include "userdb.h"

UserDBFlags nss_glue_userdb_flags(void);

int nss_pack_user_record(UserRecord *hr, struct passwd *pwd, char *buffer, size_t buflen);
int nss_pack_group_record(GroupRecord *g, char **extra_members, struct group *gr, char *buffer, size_t buflen);

int nss_pack_user_record_shadow(UserRecord *hr, struct spwd *spwd, char *buffer, size_t buflen);
int nss_pack_group_record_shadow(GroupRecord *hr, struct sgrp *sgrp, char *buffer,size_t buflen);

enum nss_status userdb_getpwnam(const char *name, struct passwd *pwd, char *buffer, size_t buflen, int *errnop);
enum nss_status userdb_getpwuid(uid_t uid, struct passwd *pwd, char *buffer, size_t buflen, int *errnop);

enum nss_status userdb_getspnam(const char *name, struct spwd *spwd, char *buffer, size_t buflen, int *errnop);

enum nss_status userdb_getgrnam(const char *name, struct group *gr, char *buffer, size_t buflen, int *errnop);
enum nss_status userdb_getgrgid(gid_t gid, struct group *gr, char *buffer, size_t buflen, int *errnop);

enum nss_status userdb_getsgnam(const char *name, struct sgrp *sgrp, char *buffer, size_t buflen, int *errnop);
