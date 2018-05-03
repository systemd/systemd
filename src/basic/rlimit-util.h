/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

#include <sys/resource.h>

#include "macro.h"

const char *rlimit_to_string(int i) _const_;
int rlimit_from_string(const char *s) _pure_;
int rlimit_from_string_harder(const char *s) _pure_;

int setrlimit_closest(int resource, const struct rlimit *rlim);

int rlimit_parse_one(int resource, const char *val, rlim_t *ret);
int rlimit_parse(int resource, const char *val, struct rlimit *ret);

int rlimit_format(const struct rlimit *rl, char **ret);

#define RLIMIT_MAKE_CONST(lim) ((struct rlimit) { lim, lim })
