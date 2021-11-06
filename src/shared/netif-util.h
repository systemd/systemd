/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include "sd-device.h"

#include "ether-addr-util.h"

int net_get_type_string(sd_device *device, uint16_t iftype, char **ret);
const char *net_get_name_persistent(sd_device *device);
int net_get_unique_predictable_data(sd_device *device, bool use_sysname, uint64_t *ret);
int net_get_unique_predictable_bytes(sd_device *device, bool use_sysname, size_t len, uint8_t *ret);
int net_verify_hardware_address(
                const char *ifname,
                bool warn_invalid,
                uint16_t iftype,
                const struct hw_addr_data *current_hw_addr,
                struct hw_addr_data *new_hw_addr);
