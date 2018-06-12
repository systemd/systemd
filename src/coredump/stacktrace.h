/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright 2014 Lennart Poettering
***/

int coredump_make_stack_trace(int fd, const char *executable, char **ret);
