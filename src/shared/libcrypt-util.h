/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#if HAVE_CRYPT_H
/* libxcrypt is a replacement for glibc's libcrypt, and libcrypt might be
 * removed from glibc at some point. As part of the removal, defines for
 * crypt(3) are dropped from unistd.h, and we must include crypt.h instead.
 *
 * Newer versions of glibc (v2.0+) already ship crypt.h with a definition
 * of crypt(3) as well, so we simply include it if it is present.  MariaDB,
 * MySQL, PostgreSQL, Perl and some other wide-spread packages do it the
 * same way since ages without any problems.
 */
#include <crypt.h>
#endif

#include <stdbool.h>
#include <stdlib.h>

int make_salt(char **ret);
int hash_password_full(const char *password, void **cd_data, int *cd_size, char **ret);
static inline int hash_password(const char *password, char **ret) {
        return hash_password_full(password, NULL, NULL, ret);
}
bool looks_like_hashed_password(const char *s);
int test_password_one(const char *hashed_password, const char *password);
int test_password_many(char **hashed_password, const char *password);
