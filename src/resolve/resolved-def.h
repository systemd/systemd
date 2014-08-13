/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#define SD_RESOLVED_DNS           ((uint64_t) 1)
#define SD_RESOLVED_LLMNR_IPV4    ((uint64_t) 2)
#define SD_RESOLVED_LLMNR_IPV6    ((uint64_t) 4)
#define SD_RESOLVED_LLMNR         (SD_RESOLVED_LLMNR_IPV4|SD_RESOLVED_LLMNR_IPV6)

#define SD_RESOLVED_FLAGS_ALL     (SD_RESOLVED_DNS|SD_RESOLVED_LLMNR_IPV4|SD_RESOLVED_LLMNR_IPV6)
#define SD_RESOLVED_FLAGS_DEFAULT SD_RESOLVED_FLAGS_ALL
