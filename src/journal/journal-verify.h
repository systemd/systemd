/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "journal-file.h"

int journal_file_verify(JournalFile *f, const char *key, usec_t *first_contained, usec_t *last_validated, usec_t *last_contained, bool show_progress);
