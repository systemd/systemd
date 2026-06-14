/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef struct LinkInfo LinkInfo;

int link_info_parse_description(LinkInfo *link, sd_varlink *vl);
