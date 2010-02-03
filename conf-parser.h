/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef fooconfparserhfoo
#define fooconfparserhfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>

/* An abstract parser for simple, line based, shallow configuration
 * files consisting of variable assignments only. */

typedef int (*ConfigParserCallback)(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);

/* Wraps info for parsing a specific configuration variable */
typedef struct ConfigItem {
        const char *lvalue; /* name of the variable */
        ConfigParserCallback parse; /* Function that is called to parse the variable's value */
        void *data; /* Where to store the variable's data */
        const char *section;
} ConfigItem;

/* The configuration file parsing routine. Expects a table of
 * config_items in *t that is terminated by an item where lvalue is
 * NULL */
int config_parse(const char *filename, FILE *f, const char* const * sections, const ConfigItem *t, void *userdata);

/* Generic parsers */
int config_parse_int(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);
int config_parse_unsigned(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);
int config_parse_size(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);
int config_parse_bool(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);
int config_parse_string(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);
int config_parse_path(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);
int config_parse_strv(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);

#endif
