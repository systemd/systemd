/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int start_transient_scope(sd_bus *bus, const char *machine_name, bool allow_pidfd, char **ret_scope);
