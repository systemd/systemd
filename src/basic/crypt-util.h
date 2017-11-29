/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2017 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#if HAVE_LIBCRYPTSETUP
#include <libcryptsetup.h>

#include "macro.h"

/* libcryptsetup define for any LUKS version, compatible with libcryptsetup 1.x */
#ifndef CRYPT_LUKS
#define CRYPT_LUKS NULL
#endif

DEFINE_TRIVIAL_CLEANUP_FUNC(struct crypt_device *, crypt_free);

void cryptsetup_log_glue(int level, const char *msg, void *usrptr);
#endif
