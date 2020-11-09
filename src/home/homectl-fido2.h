/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "json.h"

int identity_add_fido2_parameters(JsonVariant **v, const char *device);

int list_fido2_devices(void);

int find_fido2_auto(char **ret);
