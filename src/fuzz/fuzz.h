/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stddef.h>
#include <stdint.h>

/* The entry point into the fuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* https://docs.fuzzbuzz.io/developer-documentation/porting-targets-to-fuzzbuzz/libfuzzer-targets */
int FuzzerEntrypoint(const uint8_t *data, size_t size);
