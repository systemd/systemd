/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

const char *ip_protocol_to_name(int id);
int ip_protocol_from_name(const char *name);
int parse_ip_protocol(const char *s);
