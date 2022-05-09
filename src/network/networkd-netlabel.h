/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

void address_add_netlabel(const Address *address);
void address_del_netlabel(const Address *address);

int config_parse_netlabel(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                Set **set);

CONFIG_PARSER_PROTOTYPE(config_parse_address_netlabel);
CONFIG_PARSER_PROTOTYPE(config_parse_dhcp_or_ra_netlabel);
