/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int identity_add_fido2_parameters(sd_json_variant **v, const char *device, Fido2EnrollFlags lock_with, int cred_alg);
