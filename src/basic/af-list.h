/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

const char* af_to_name(int id);
int af_from_name(const char *name);

const char* af_to_name_short(int id);

const char* af_to_ipv4_ipv6(int id);
int af_from_ipv4_ipv6(const char *af);

int af_max(void);
