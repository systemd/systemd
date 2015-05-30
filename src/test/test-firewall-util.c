/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include "log.h"
#include "firewall-util.h"

#define MAKE_IN_ADDR_UNION(a,b,c,d) (union in_addr_union) { .in.s_addr = htobe32((uint32_t) (a) << 24 | (uint32_t) (b) << 16 | (uint32_t) (c) << 8 | (uint32_t) (d))}

int main(int argc, char *argv[]) {
        int r;
        uint64_t handle;
        log_set_max_level(LOG_DEBUG);

        r = fw_add_masquerade(AF_INET, 0, NULL, 0, "foobar", NULL, 0, &handle);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_remove_masquerade(handle);
        if (r < 0)
                log_error_errno(r, "Failed to remove firewall rule: %m");


        r = fw_add_local_dnat(AF_INET, IPPROTO_TCP, NULL, NULL, 0, NULL, 0, 4711, &MAKE_IN_ADDR_UNION(1, 2, 3, 4), 815, &handle);
        if (r < 0)
                log_error_errno(r, "Failed to modify firewall: %m");

        r = fw_remove_local_dnat(handle);
        if (r < 0)
                log_error_errno(r, "Failed to remove firewall rule: %m");

        return 0;
}
