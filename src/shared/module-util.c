/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "module-util.h"
#include "proc-cmdline.h"
#include "strv.h"

#if HAVE_KMOD

static void *libkmod_dl = NULL;

DLSYM_PROTOTYPE(kmod_list_next) = NULL;
DLSYM_PROTOTYPE(kmod_load_resources) = NULL;
DLSYM_PROTOTYPE(kmod_module_get_initstate) = NULL;
DLSYM_PROTOTYPE(kmod_module_get_module) = NULL;
DLSYM_PROTOTYPE(kmod_module_get_name) = NULL;
DLSYM_PROTOTYPE(kmod_module_new_from_lookup) = NULL;
DLSYM_PROTOTYPE(kmod_module_probe_insert_module) = NULL;
DLSYM_PROTOTYPE(kmod_module_unref) = NULL;
DLSYM_PROTOTYPE(kmod_module_unref_list) = NULL;
DLSYM_PROTOTYPE(kmod_new) = NULL;
DLSYM_PROTOTYPE(kmod_set_log_fn) = NULL;
DLSYM_PROTOTYPE(kmod_unref) = NULL;
DLSYM_PROTOTYPE(kmod_validate_resources) = NULL;

int dlopen_libkmod(void) {
        ELF_NOTE_DLOPEN("kmod",
                        "Support for loading kernel modules",
                        ELF_NOTE_DLOPEN_PRIORITY_RECOMMENDED,
                        "libkmod.so.2");

        return dlopen_many_sym_or_warn(
                        &libkmod_dl,
                        "libkmod.so.2",
                        LOG_DEBUG,
                        DLSYM_ARG(kmod_list_next),
                        DLSYM_ARG(kmod_load_resources),
                        DLSYM_ARG(kmod_module_get_initstate),
                        DLSYM_ARG(kmod_module_get_module),
                        DLSYM_ARG(kmod_module_get_name),
                        DLSYM_ARG(kmod_module_new_from_lookup),
                        DLSYM_ARG(kmod_module_probe_insert_module),
                        DLSYM_ARG(kmod_module_unref),
                        DLSYM_ARG(kmod_module_unref_list),
                        DLSYM_ARG(kmod_new),
                        DLSYM_ARG(kmod_set_log_fn),
                        DLSYM_ARG(kmod_unref),
                        DLSYM_ARG(kmod_validate_resources));
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        char ***denylist = ASSERT_PTR(data);
        int r;

        if (proc_cmdline_key_streq(key, "module_blacklist")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = strv_split_and_extend(denylist, value, ",", /* filter_duplicates = */ true);
                if (r < 0)
                        return r;
        }

        return 0;
}

int module_load_and_warn(struct kmod_ctx *ctx, const char *module, bool verbose) {
        _cleanup_(sym_kmod_module_unref_listp) struct kmod_list *modlist = NULL;
        _cleanup_strv_free_ char **denylist = NULL;
        bool denylist_parsed = false;
        struct kmod_list *itr;
        int r;

        assert(ctx);
        assert(module);

        /* verbose==true means we should log at non-debug level if we
         * fail to find or load the module. */

        log_debug("Loading module: %s", module);

        r = sym_kmod_module_new_from_lookup(ctx, module, &modlist);
        if (r < 0)
                return log_full_errno(verbose ? LOG_ERR : LOG_DEBUG, r,
                                      "Failed to look up module alias '%s': %m", module);

        if (!modlist)
                return log_full_errno(verbose ? LOG_ERR : LOG_DEBUG,
                                      SYNTHETIC_ERRNO(ENOENT),
                                      "Failed to find module '%s'", module);

        sym_kmod_list_foreach(itr, modlist) {
                _cleanup_(sym_kmod_module_unrefp) struct kmod_module *mod = NULL;
                int state, err;

                mod = sym_kmod_module_get_module(itr);
                state = sym_kmod_module_get_initstate(mod);

                switch (state) {
                case KMOD_MODULE_BUILTIN:
                        log_full(verbose ? LOG_INFO : LOG_DEBUG,
                                 "Module '%s' is built in", sym_kmod_module_get_name(mod));
                        break;

                case KMOD_MODULE_LIVE:
                        log_debug("Module '%s' is already loaded", sym_kmod_module_get_name(mod));
                        break;

                default:
                        err = sym_kmod_module_probe_insert_module(
                                        mod,
                                        KMOD_PROBE_APPLY_BLACKLIST,
                                        /* extra_options= */ NULL,
                                        /* run_install= */ NULL,
                                        /* data= */ NULL,
                                        /* print_action= */ NULL);
                        if (err == 0)
                                log_full(verbose ? LOG_INFO : LOG_DEBUG,
                                         "Inserted module '%s'", sym_kmod_module_get_name(mod));
                        else if (err == KMOD_PROBE_APPLY_BLACKLIST)
                                log_full(verbose ? LOG_INFO : LOG_DEBUG,
                                         "Module '%s' is deny-listed (by kmod)", sym_kmod_module_get_name(mod));
                        else {
                                assert(err < 0);

                                if (err == -EPERM) {
                                        if (!denylist_parsed) {
                                                r = proc_cmdline_parse(parse_proc_cmdline_item, &denylist, 0);
                                                if (r < 0)
                                                        log_full_errno(!verbose ? LOG_DEBUG : LOG_WARNING,
                                                                       r,
                                                                       "Failed to parse kernel command line, ignoring: %m");

                                                denylist_parsed = true;
                                        }
                                        if (strv_contains(denylist, sym_kmod_module_get_name(mod))) {
                                                log_full(verbose ? LOG_INFO : LOG_DEBUG,
                                                         "Module '%s' is deny-listed (by kernel)", sym_kmod_module_get_name(mod));
                                                continue;
                                        }
                                }

                                log_full_errno(!verbose ? LOG_DEBUG :
                                               err == -ENODEV ? LOG_NOTICE :
                                               err == -ENOENT ? LOG_WARNING :
                                                                LOG_ERR,
                                               err,
                                               "Failed to insert module '%s': %m",
                                               sym_kmod_module_get_name(mod));
                                if (!IN_SET(err, -ENODEV, -ENOENT))
                                        r = err;
                        }
                }
        }

        return r;
}

_printf_(6,0) static void systemd_kmod_log(
                void *data,
                int priority,
                const char *file,
                int line,
                const char *fn,
                const char *format,
                va_list args) {

        log_internalv(priority, 0, file, line, fn, format, args);
}

int module_setup_context(struct kmod_ctx **ret) {
        _cleanup_(sym_kmod_unrefp) struct kmod_ctx *ctx = NULL;
        int r;

        assert(ret);

        r = dlopen_libkmod();
        if (r < 0)
                return r;

        ctx = sym_kmod_new(NULL, NULL);
        if (!ctx)
                return -ENOMEM;

        (void) sym_kmod_load_resources(ctx);
        sym_kmod_set_log_fn(ctx, systemd_kmod_log, NULL);

        *ret = TAKE_PTR(ctx);
        return 0;
}

#endif
