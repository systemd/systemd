/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "user-record.h"

int fido2_use_token(UserRecord *h, UserRecord *secret, const Fido2HmacSalt *salt, char **ret);
