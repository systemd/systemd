/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "in-addr-util.h"
#include "set.h"
#include "socket-netlink.h"

int bus_message_read_id128(sd_bus_message *m, sd_id128_t *ret);

int bus_message_read_ifindex(sd_bus_message *message, sd_bus_error *error, int *ret);
int bus_message_read_family(sd_bus_message *message, sd_bus_error *error, int *ret);
int bus_message_read_in_addr_auto(sd_bus_message *message, sd_bus_error *error, int *ret_family, union in_addr_union *ret_addr);

int bus_message_read_dns_servers(
                        sd_bus_message *message,
                        sd_bus_error *error,
                        bool extended,
                        struct in_addr_full ***ret_dns,
                        size_t *ret_n_dns);

int bus_message_append_string_set(sd_bus_message *m, const Set *s);

int bus_message_dump_string(sd_bus_message *message);
int bus_message_dump_fd(sd_bus_message *message);

extern const struct hash_ops bus_message_hash_ops;
