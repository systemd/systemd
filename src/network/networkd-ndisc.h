#pragma once

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#include "networkd-link.h"

typedef struct NDiscRDNSS {
        usec_t valid_until;
        struct in6_addr address;
} NDiscRDNSS;

typedef struct NDiscDNSSL {
        usec_t valid_until;
        /* The domain name follows immediately. */
} NDiscDNSSL;

static inline char* NDISC_DNSSL_DOMAIN(const NDiscDNSSL *n) {
        return ((char*) n) + ALIGN(sizeof(NDiscDNSSL));
}

int ndisc_configure(Link *link);
void ndisc_vacuum(Link *link);
void ndisc_flush(Link *link);
