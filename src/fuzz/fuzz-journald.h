/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "journald-server.h"

void fuzz_journald_processing_function(
                const uint8_t *data,
                size_t size,
                void (*f)(Server *s, const char *buf, size_t raw_len, const struct ucred *ucred, const struct timeval *tv, const char *label, size_t label_len)
);
