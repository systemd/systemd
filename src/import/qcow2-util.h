/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering
***/

int qcow2_detect(int fd);
int qcow2_convert(int qcow2_fd, int raw_fd);
