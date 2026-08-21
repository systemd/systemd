/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int acquire_journal(sd_journal **ret, char * const *matches);
int focus(sd_journal *j);
