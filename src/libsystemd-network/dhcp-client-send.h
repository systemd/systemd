/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

int dhcp_client_send_message(sd_dhcp_client *client, uint8_t type);
