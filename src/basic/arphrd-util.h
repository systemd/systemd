/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stddef.h>

const char *arphrd_to_name(int id);
int arphrd_from_name(const char *name);

size_t arphrd_to_hw_addr_len(uint16_t arphrd);
