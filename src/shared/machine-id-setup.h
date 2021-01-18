/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

int machine_id_commit(const char *root);
int machine_id_setup(const char *root, bool force_transient, sd_id128_t requested, sd_id128_t *ret);
