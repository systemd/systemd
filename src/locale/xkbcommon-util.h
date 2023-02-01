/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_XKBCOMMON
#include <xkbcommon/xkbcommon.h>

extern struct xkb_context* (*sym_xkb_context_new)(enum xkb_context_flags flags);
extern void (*sym_xkb_context_unref)(struct xkb_context *context);
extern void (*sym_xkb_context_set_log_fn)(
                struct xkb_context *context,
                void (*log_fn)(
                        struct xkb_context *context,
                        enum xkb_log_level level,
                        const char *format,
                        va_list args));
extern struct xkb_keymap* (*sym_xkb_keymap_new_from_names)(
                struct xkb_context *context,
                const struct xkb_rule_names *names,
                enum xkb_keymap_compile_flags flags);
extern void (*sym_xkb_keymap_unref)(struct xkb_keymap *keymap);

int verify_xkb_rmlvo(const char *model, const char *layout, const char *variant, const char *options);

#else

static inline int verify_xkb_rmlvo(const char *model, const char *layout, const char *variant, const char *options) {
        return 0;
}

#endif
