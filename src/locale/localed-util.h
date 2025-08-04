/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/stat.h>
#include <syslog.h>

#include "forward.h"
#include "locale-setup.h"
#include "vconsole-util.h"

typedef struct Context {
        sd_bus_message *locale_cache;
        LocaleContext locale_context;

        sd_bus_message *x11_cache;
        struct stat x11_stat;
        X11Context x11_from_xorg;
        X11Context x11_from_vc;

        sd_bus_message *vc_cache;
        struct stat vc_stat;
        VCContext vc;

        Hashmap *polkit_registry;
} Context;

int x11_context_verify_and_warn(const X11Context *xc, int log_level, sd_bus_error *error);
static inline int x11_context_verify(const X11Context *xc) {
        return x11_context_verify_and_warn(xc, LOG_DEBUG, NULL);
}
X11Context *context_get_x11_context(Context *c);

int vc_context_verify_and_warn(const VCContext *vc, int log_level, sd_bus_error *error);
static inline int vc_context_verify(const VCContext *vc) {
        return vc_context_verify_and_warn(vc, LOG_DEBUG, NULL);
}

int locale_read_data(Context *c, sd_bus_message *m);
int vconsole_read_data(Context *c, sd_bus_message *m);
int x11_read_data(Context *c, sd_bus_message *m);

void context_clear(Context *c);
int vconsole_write_data(Context *c);
int x11_write_data(Context *c);

bool locale_gen_check_available(void);
int locale_gen_enable_locale(const char *locale);
int locale_gen_run(void);
