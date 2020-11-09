/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/types.h>

int setup_seccomp(uint64_t cap_list_retain, char **syscall_allow_list, char **syscall_deny_list);
