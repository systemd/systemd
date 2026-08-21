/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int print_info(FILE *file, sd_journal *j, bool need_space);
int print_entry(sd_journal *j, size_t n_found, Table *t);
