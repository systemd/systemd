/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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

#include <gcrypt.h>

#include "hexdecoct.h"
#include "gcrypt-util.h"

void initialize_libgcrypt(bool secmem) {
        const char *p;
        if (gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
                return;

        p = gcry_check_version("1.4.5");
        assert(p);

        /* Turn off "secmem". Clients which whish to make use of this
         * feature should initialize the library manually */
        if (!secmem)
                gcry_control(GCRYCTL_DISABLE_SECMEM);
        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}
