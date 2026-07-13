/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

bool field_list_has_scope_options(void);
int add_filters(sd_journal *j, char **matches);
