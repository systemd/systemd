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

#define SD_RESOLVED_DNS           (UINT64_C(1) << 0)
#define SD_RESOLVED_LLMNR_IPV4    (UINT64_C(1) << 1)
#define SD_RESOLVED_LLMNR_IPV6    (UINT64_C(1) << 2)
#define SD_RESOLVED_MDNS_IPV4     (UINT64_C(1) << 3)
#define SD_RESOLVED_MDNS_IPV6     (UINT64_C(1) << 4)
#define SD_RESOLVED_NO_CNAME      (UINT64_C(1) << 5)
#define SD_RESOLVED_NO_TXT        (UINT64_C(1) << 6)
#define SD_RESOLVED_NO_ADDRESS    (UINT64_C(1) << 7)
#define SD_RESOLVED_NO_SEARCH     (UINT64_C(1) << 8)
#define SD_RESOLVED_AUTHENTICATED (UINT64_C(1) << 9)

#define SD_RESOLVED_LLMNR         (SD_RESOLVED_LLMNR_IPV4|SD_RESOLVED_LLMNR_IPV6)
#define SD_RESOLVED_MDNS          (SD_RESOLVED_MDNS_IPV4|SD_RESOLVED_MDNS_IPV6)

#define SD_RESOLVED_PROTOCOLS_ALL (SD_RESOLVED_MDNS|SD_RESOLVED_LLMNR|SD_RESOLVED_DNS)
