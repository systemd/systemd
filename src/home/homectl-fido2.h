/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"
#include "libfido2-util.h"

int identity_add_fido2_parameters(JsonVariant **v, const char *device, Fido2EnrollFlags lock_with, int cred_alg);
