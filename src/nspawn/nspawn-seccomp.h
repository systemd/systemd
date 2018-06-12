/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright 2016 Lennart Poettering
***/

#include <sys/types.h>

int setup_seccomp(uint64_t cap_list_retain, char **syscall_whitelist, char **syscall_blacklist);
