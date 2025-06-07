/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-manager.h"

void dummy_manager_init(Manager *m, const uint8_t *buffer, size_t size);

void fuzz_journald_processing_function(
                const uint8_t *data,
                size_t size,
                void (*f)(Manager *m, const char *buf, size_t raw_len, const struct ucred *ucred, const struct timeval *tv, const char *label, size_t label_len)
);
