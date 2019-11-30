/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "in-addr-util.h"

int in_addr_ifindex_name_from_string_auto(const char *s, int *family, union in_addr_union *ret, int *ifindex, char **server_name);
