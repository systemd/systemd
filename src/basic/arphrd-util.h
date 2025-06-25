/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

const char* arphrd_to_name(int id) _const_;
int arphrd_from_name(const char *name) _pure_;

size_t arphrd_to_hw_addr_len(uint16_t arphrd) _const_;
