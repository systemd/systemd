/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-manager.h"

typedef void (*journal_process_t)(
                Manager *m,
                const char *buf,
                size_t raw_len,
                const struct ucred *ucred,
                const struct timeval *tv,
                const char *label,
                size_t label_len);

void dummy_manager_new(Manager **ret, const uint8_t *buffer, size_t size);

void fuzz_journald_processing_function(
                const uint8_t *data,
                size_t size,
                journal_process_t f);
