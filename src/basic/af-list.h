/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

const char* af_to_name(int id) _const_;
int af_from_name(const char *name) _pure_;

const char* af_to_name_short(int id) _const_;

const char* af_to_ipv4_ipv6(int id) _const_;
int af_from_ipv4_ipv6(const char *af) _pure_;

int af_max(void) _const_;
