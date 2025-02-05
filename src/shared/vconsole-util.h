/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "log.h"
#include "sd-bus.h"

typedef struct X11Context {
        char *layout;
        char *model;
        char *variant;
        char *options;
} X11Context;

typedef struct VCContext {
        char *keymap;
        char *toggle;
} VCContext;

void x11_context_clear(X11Context *xc);
void x11_context_replace(X11Context *dest, X11Context *src);
bool x11_context_isempty(const X11Context *xc);
void x11_context_empty_to_null(X11Context *xc);
bool x11_context_is_safe(const X11Context *xc);
bool x11_context_equal(const X11Context *a, const X11Context *b);
int x11_context_copy(X11Context *dest, const X11Context *src);
int x11_context_verify_and_warn(const X11Context *xc, int log_level, sd_bus_error *error);
static inline int x11_context_verify(const X11Context *xc) {
        return x11_context_verify_and_warn(xc, LOG_DEBUG, NULL);
}

int find_converted_keymap(const X11Context *xc, char **ret);
int find_legacy_keymap(const X11Context *xc, char **ret);
int find_language_fallback(const char *lang, char **ret);

void vc_context_clear(VCContext *vc);
void vc_context_replace(VCContext *dest, VCContext *src);
bool vc_context_isempty(const VCContext *vc);
void vc_context_empty_to_null(VCContext *vc);
bool vc_context_equal(const VCContext *a, const VCContext *b);
int vc_context_copy(VCContext *dest, const VCContext *src);
int vc_context_verify_and_warn(const VCContext *vc, int log_level, sd_bus_error *error);
static inline int vc_context_verify(const VCContext *vc) {
        return vc_context_verify_and_warn(vc, LOG_DEBUG, NULL);
}

int vconsole_convert_to_x11(const VCContext *vc, X11Context *ret);
int x11_convert_to_vconsole(const X11Context *xc, VCContext *ret);

int vconsole_serialize(const VCContext *vc, const X11Context *xc, char ***ret);
