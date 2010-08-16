/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef fooshutdowndhfoo
#define fooshutdowndhfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "util.h"
#include "macro.h"

/* This is a private message, we don't care much about ABI
 * stability. */

_packed_ struct shutdownd_command {
        usec_t elapse;
        char mode; /* H, P, r, i.e. the switches usually passed to
                    * shutdown to select whether to halt, power-off or
                    * reboot the machine */
        bool warn_wall;

        /* Yepp, sometimes we are lazy and use fixed-size strings like
         * this one. Shame on us. But then again, we'd have to
         * pre-allocate the receive buffer anyway, so there's nothing
         * too bad here. */
        char wall_message[4096];
};

#endif
