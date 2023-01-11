/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/stat.h>

#include "sd-bus.h"

#include "hashmap.h"
#include "locale-setup.h"

typedef struct X11Context {
        char *layout;
        char *model;
        char *variant;
        char *options;
} X11Context;

typedef struct Context {
        sd_bus_message *locale_cache;
        LocaleContext locale_context;

        sd_bus_message *x11_cache;
        struct stat x11_stat;
        X11Context x11_from_xorg;
        X11Context x11_from_vc;

        sd_bus_message *vc_cache;
        struct stat vc_stat;
        char *vc_keymap;
        char *vc_keymap_toggle;

        Hashmap *polkit_registry;
} Context;

void x11_context_empty_to_null(X11Context *xc);
bool x11_context_is_safe(const X11Context *xc);
bool x11_context_equal(const X11Context *a, const X11Context *b);
int x11_context_copy(X11Context *dest, const X11Context *src);

X11Context *context_get_x11_context_safe(Context *c);

int find_converted_keymap(const X11Context *xc, char **ret);
int find_legacy_keymap(const X11Context *xc, char **ret);
int find_language_fallback(const char *lang, char **ret);

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
