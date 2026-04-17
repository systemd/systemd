/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "dhcp-message.h"

int dump_dhcp_options(sd_dhcp_message *message, char * const *args);
int dump_dhcp_header(sd_dhcp_message *message);
