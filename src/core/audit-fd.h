/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering
***/

int get_audit_fd(void);
void close_audit_fd(void);
