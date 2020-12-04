/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdio.h>

int sethostname_idempotent(const char *s);

int shorten_overlong(const char *s, char **ret);

int read_etc_hostname_stream(FILE *f, char **ret);
int read_etc_hostname(const char *path, char **ret);

int hostname_setup(void);
