/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Daniel Buch

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

#include "util.h"

DEFINE_TRIVIAL_CLEANUP_FUNC(asyncns_t*, asyncns_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(unsigned char *, asyncns_freeanswer);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct addrinfo*, asyncns_freeaddrinfo);
#define _cleanup_asyncns_free_ _cleanup_(asyncns_freep)
#define _cleanup_asyncns_answer_free_ _cleanup_(asyncns_freeanswerp)
#define _cleanup_asyncns_addrinfo_free_ _cleanup_(asyncns_freeaddrinfop)
