/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int journal_directory_vacuum(const char *directory, uint64_t max_use, uint64_t n_max_files, usec_t max_retention_usec, usec_t *oldest_usec, bool verbose);
