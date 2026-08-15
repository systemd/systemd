/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journal-file.h"

int journal_file_verify(
                JournalFile *f,
                const char *key,
                usec_t *ret_first_contained,
                usec_t *ret_last_validated,
                usec_t *ret_last_contained,
                bool show_progress);
