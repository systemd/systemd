/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "icmp6-util.h"

typedef int (*send_ra_t)(uint8_t flags);

extern send_ra_t send_ra_function;
extern int test_fd[2];
