/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

int chattr_fd(int fd, unsigned value, unsigned mask, unsigned *previous);
int chattr_path(const char *p, unsigned value, unsigned mask, unsigned *previous);

int read_attr_fd(int fd, unsigned *ret);
int read_attr_path(const char *p, unsigned *ret);
