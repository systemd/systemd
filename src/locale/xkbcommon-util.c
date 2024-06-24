/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dlfcn-util.h"
#include "log.h"
#include "macro.h"
#include "string-util.h"
#include "xkbcommon-util.h"

#if HAVE_XKBCOMMON
static void *xkbcommon_dl = NULL;

DLSYM_PROTOTYPE(xkb_context_new) = NULL;
DLSYM_PROTOTYPE(xkb_context_unref) = NULL;
DLSYM_PROTOTYPE(xkb_context_set_log_fn) = NULL;
DLSYM_PROTOTYPE(xkb_keymap_new_from_names) = NULL;
DLSYM_PROTOTYPE(xkb_keymap_unref) = NULL;

static int dlopen_xkbcommon(void) {
        ELF_NOTE_DLOPEN("xkbcommon",
                        "Support for keyboard locale descriptions",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED, "libxkbcommon.so.0");

        return dlopen_many_sym_or_warn(
                        &xkbcommon_dl, "libxkbcommon.so.0", LOG_DEBUG,
                        DLSYM_ARG(xkb_context_new),
                        DLSYM_ARG(xkb_context_unref),
                        DLSYM_ARG(xkb_context_set_log_fn),
                        DLSYM_ARG(xkb_keymap_new_from_names),
                        DLSYM_ARG(xkb_keymap_unref));
}

_printf_(3, 0)
static void log_xkb(struct xkb_context *ctx, enum xkb_log_level lvl, const char *format, va_list args) {
        const char *fmt;

        fmt = strjoina("libxkbcommon: ", format);
        DISABLE_WARNING_FORMAT_NONLITERAL;
        log_internalv(LOG_DEBUG, 0, PROJECT_FILE, __LINE__, __func__, fmt, args);
        REENABLE_WARNING;
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct xkb_context *, sym_xkb_context_unref, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(struct xkb_keymap *, sym_xkb_keymap_unref, NULL);

int verify_xkb_rmlvo(const char *model, const char *layout, const char *variant, const char *options) {
        _cleanup_(sym_xkb_context_unrefp) struct xkb_context *ctx = NULL;
        _cleanup_(sym_xkb_keymap_unrefp) struct xkb_keymap *km = NULL;
        const struct xkb_rule_names rmlvo = {
                .model          = model,
                .layout         = layout,
                .variant        = variant,
                .options        = options,
        };
        int r;

        /* Compile keymap from RMLVO information to check out its validity */

        r = dlopen_xkbcommon();
        if (r < 0)
                return r;

        ctx = sym_xkb_context_new(XKB_CONTEXT_NO_ENVIRONMENT_NAMES);
        if (!ctx)
                return -ENOMEM;

        sym_xkb_context_set_log_fn(ctx, log_xkb);

        km = sym_xkb_keymap_new_from_names(ctx, &rmlvo, XKB_KEYMAP_COMPILE_NO_FLAGS);
        if (!km)
                return -EINVAL;

        return 0;
}

#endif
