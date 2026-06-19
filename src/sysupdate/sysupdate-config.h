/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

int config_parse_url_specifiers(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_url_specifiers_many(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

extern const Specifier specifier_table[];
