/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

char *sysctl_normalize(char *s);
int sysctl_read(const char *property, char **value);
int sysctl_write(const char *property, const char *value);

