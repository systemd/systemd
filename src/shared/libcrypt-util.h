/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

#if HAVE_LIBCRYPT
int make_salt(char **ret);
int hash_password(const char *password, char **ret);
int test_password_one(const char *hashed_password, const char *password);
int test_password_many(char **hashed_password, const char *password);

#else

static inline int hash_password(const char *password, char **ret) {
        return -EOPNOTSUPP;
}
#endif

bool looks_like_hashed_password(const char *s);
