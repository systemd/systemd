/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering
***/

char* setup_fake_runtime_dir(void);
const char* get_testdata_dir(const char *suffix);
