/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/stat.h>

#include "sd-bus.h"

#include "hashmap.h"
#include "locale-setup.h"

typedef struct Context {
        sd_bus_message *locale_cache;
        LocaleContext locale_context;

        sd_bus_message *x11_cache;
        struct stat x11_stat;
        char *x11_layout;
        char *x11_model;
        char *x11_variant;
        char *x11_options;

        sd_bus_message *vc_cache;
        struct stat vc_stat;
        char *vc_keymap;
        char *vc_keymap_toggle;

        Hashmap *polkit_registry;
} Context;

int find_converted_keymap(const char *x11_layout, const char *x11_variant, char **new_keymap);
int find_legacy_keymap(Context *c, char **new_keymap);
int find_language_fallback(const char *lang, char **language);

int locale_read_data(Context *c, sd_bus_message *m);
int vconsole_read_data(Context *c, sd_bus_message *m);
int x11_read_data(Context *c, sd_bus_message *m);

void context_clear(Context *c);
int vconsole_convert_to_x11(Context *c);
int vconsole_write_data(Context *c);
int x11_convert_to_vconsole(Context *c);
int x11_write_data(Context *c);

bool locale_gen_check_available(void);
int locale_gen_enable_locale(const char *locale);
int locale_gen_run(void);
