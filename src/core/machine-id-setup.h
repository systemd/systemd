/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering
***/

int machine_id_commit(const char *root);
int machine_id_setup(const char *root, sd_id128_t requested, sd_id128_t *ret);
