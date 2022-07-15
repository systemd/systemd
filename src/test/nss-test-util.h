/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <nss.h>
#include <stdint.h>

const char* nss_status_to_string(enum nss_status status, char *buf, size_t buf_len);
void* nss_open_handle(const char *dir, const char *module, int flags);
