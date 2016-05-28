/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering
  Copyright 2013 Kay Sievers

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
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
