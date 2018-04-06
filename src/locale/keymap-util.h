/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering
  Copyright 2013 Kay Sievers
***/

#include "locale-util.h"

typedef struct Context {
        char *locale[_VARIABLE_LC_MAX];

        char *x11_layout;
        char *x11_model;
        char *x11_variant;
        char *x11_options;

        char *vc_keymap;
        char *vc_keymap_toggle;
} Context;

int find_converted_keymap(const char *x11_layout, const char *x11_variant, char **new_keymap);
int find_legacy_keymap(Context *c, char **new_keymap);
int find_language_fallback(const char *lang, char **language);

int context_read_data(Context *c);
void context_free(Context *c);
int vconsole_convert_to_x11(Context *c);
int vconsole_write_data(Context *c);
int x11_convert_to_vconsole(Context *c);
int x11_write_data(Context *c);
void locale_simplify(Context *c);
int locale_write_data(Context *c, char ***settings);
