/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

bool link_xlat_enabled(Link *link);
int xlat_start(Link *link);
int xlat_stop(Link *link);
void xlat_done(Link *link);
int xlat_check_address(Link *link);
