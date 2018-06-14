/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2018 Jonathan Rudenberg
***/

#include <stddef.h>
#include <stdint.h>

/* The entry point into the fuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
