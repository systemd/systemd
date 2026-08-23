/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int validate_dev_path(const char *what, const char *path);
int validate_fields(const char *name, const char *src, const char *dst,
                    const char *meta, const char *options);
