/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosdmessageshfoo
#define foosdmessageshfoo

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

#include <systemd/sd-id128.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SD_MESSAGE_JOURNAL_START   SD_ID128_MAKE(f7,73,79,a8,49,0b,40,8b,be,5f,69,40,50,5a,77,7b)
#define SD_MESSAGE_JOURNAL_STOP    SD_ID128_MAKE(d9,3f,b3,c9,c2,4d,45,1a,97,ce,a6,15,ce,59,c0,0b)
#define SD_MESSAGE_JOURNAL_DROPPED SD_ID128_MAKE(a5,96,d6,fe,7b,fa,49,94,82,8e,72,30,9e,95,d6,1e)

#define SD_MESSAGE_COREDUMP        SD_ID128_MAKE(fc,2e,22,bc,6e,e6,47,b6,b9,07,29,ab,34,a2,50,b1)

#ifdef __cplusplus
}
#endif

#endif
