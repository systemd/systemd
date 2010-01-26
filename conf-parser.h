/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef fooconfparserhfoo
#define fooconfparserhfoo

#include <stdio.h>

/* An abstract parser for simple, line based, shallow configuration
 * files consisting of variable assignments only. */

typedef int (*config_parser_cb_t)(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);

/* Wraps info for parsing a specific configuration variable */
typedef struct ConfigItem {
        const char *lvalue; /* name of the variable */
        config_parser_cb_t parse; /* Function that is called to parse the variable's value */
        void *data; /* Where to store the variable's data */
        const char *section;
} ConfigItem;

/* The configuration file parsing routine. Expects a table of
 * config_items in *t that is terminated by an item where lvalue is
 * NULL */
int config_parse(const char *filename, const char* const * sections, const ConfigItem *t, void *userdata);

/* Generic parsers */
int config_parse_int(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);
int config_parse_unsigned(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);
int config_parse_size(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);
int config_parse_bool(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);
int config_parse_string(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);
int config_parse_path(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);
int config_parse_strv(const char *filename, unsigned line, const char *section, const char *lvalue, const char *rvalue, void *data, void *userdata);

#endif
