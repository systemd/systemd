/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

int make_salt(char **ret);
int hash_password(const char *password, char **ret);
int test_password_one(const char *hashed_password, const char *password);
int test_password_many(char **hashed_password, const char *password);
bool looks_like_hashed_password(const char *s);
