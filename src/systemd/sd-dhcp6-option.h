/* SPDX-License-Identifier: LGPL-2.1+
 * Copyright © 2020 VMware, Inc.
 */

#ifndef foosddhcp6optionhfoo
#define foosddhcp6optionhfoo

#include <inttypes.h>
#include <sys/types.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_dhcp6_option sd_dhcp6_option;

int sd_dhcp6_option_new(uint8_t option, const void *data, size_t length, sd_dhcp6_option **ret);
sd_dhcp6_option *sd_dhcp6_option_ref(sd_dhcp6_option *ra);
sd_dhcp6_option *sd_dhcp6_option_unref(sd_dhcp6_option *ra);

_SD_DEFINE_POINTER_CLEANUP_FUNC(sd_dhcp6_option, sd_dhcp6_option_unref);

_SD_END_DECLARATIONS;

#endif
