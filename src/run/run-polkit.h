/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int polkit_check_authorization(sd_bus *bus, PolkitFlags flags, char **ret_tmpauthz_id);
int polkit_revoke_temporary_authorization_by_id(sd_bus *bus, const char *id);
int polkit_revoke_temporary_authorizations(sd_bus *bus);
