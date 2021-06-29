/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stdint.h>

int parse_socket_bind_item(
        const char *str,
        int *address_family,
        int *ip_protocol,
        uint16_t *nr_ports,
        uint16_t *port_min);
