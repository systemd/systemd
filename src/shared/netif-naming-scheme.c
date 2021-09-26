/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "netif-naming-scheme.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "strv.h"

static NamingScheme naming_schemes[] = {
        { "v238", NAMING_V238 },
        { "v239", NAMING_V239 },
        { "v240", NAMING_V240 },
        { "v241", NAMING_V241 },
        { "v243", NAMING_V243 },
        { "v245", NAMING_V245 },
        { "v247", NAMING_V247 },
        { "v249", NAMING_V249 },
        /* … add more schemes here, as the logic to name devices is updated … */
};

static const struct {
        NamingSchemeFlags flag;
        const char *name;
} naming_scheme_flags[] = {
        { .name = "sr_iov_v",           .flag = NAMING_SR_IOV_V },
        { .name = "npar_ari",           .flag = NAMING_NPAR_ARI },
        { .name = "infiniband",         .flag = NAMING_INFINIBAND },
        { .name = "zero_acpi_index",    .flag = NAMING_ZERO_ACPI_INDEX },
        { .name = "allow_rerenames",    .flag = NAMING_ALLOW_RERENAMES },
        { .name = "stable_virtual_macs",.flag = NAMING_STABLE_VIRTUAL_MACS },
        { .name = "netdevsim",          .flag = NAMING_NETDEVSIM },
        { .name = "label_noprefix",     .flag = NAMING_LABEL_NOPREFIX },
        { .name = "nspawn_long_hash",   .flag = NAMING_NSPAWN_LONG_HASH },
        { .name = "bridge_no_slot",     .flag = NAMING_BRIDGE_NO_SLOT },
        { .name = "slot_function_id",   .flag = NAMING_SLOT_FUNCTION_ID },
        { .name = "16bit_index",        .flag = NAMING_16BIT_INDEX },
        { .name = "replace_strictly",   .flag = NAMING_REPLACE_STRICTLY },
};

static NamingSchemeFlags naming_scheme_flag_from_name(const char *name) {

        for (size_t i = 0; i < ELEMENTSOF(naming_scheme_flags); i++)
                if (streq(name, naming_scheme_flags[i].name))
                        return naming_scheme_flags[i].flag;

        return 0;
}

static const NamingScheme* naming_scheme_from_name(const char *name) {
        _cleanup_strv_free_ char **l = NULL;
        NamingScheme *ns = NULL;
        char *base, **s;
        size_t i;

        assert(name);

        l = strv_split(name, "+");
        if (!l)
                return NULL;

        base = l[0];
        if (streq(base, "latest"))
                ns = naming_schemes + ELEMENTSOF(naming_schemes) - 1;
        else
                for (i = 0; i < ELEMENTSOF(naming_schemes); i++)
                        if (streq(base, naming_schemes[i].name)) {
                                ns = naming_schemes + i;
                                break;
                        }

        if (!ns) {
                log_warning("Unknown interface naming scheme '%s' requested, ignoring.", base);
                return NULL;
        }

        log_info("Using interface naming scheme '%s'", ns->name);

        STRV_FOREACH(s, l+1) {
                NamingSchemeFlags flag = naming_scheme_flag_from_name(*s);

                if (!flag) {
                        log_warning("Unknown interface naming scheme flag '%s', ignoring.", *s);
                        continue;
                }

                log_info("Extending interface naming scheme with flag: %s", *s);
                ns->flags |= flag;
        }

        return ns;
}

const NamingScheme* naming_scheme(void) {
        static const NamingScheme *cache = NULL;
        _cleanup_free_ char *buffer = NULL;
        const char *e, *k;

        if (cache)
                return cache;

        /* Acquire setting from the kernel command line */
        (void) proc_cmdline_get_key("net.naming-scheme", 0, &buffer);

        /* Also acquire it from an env var */
        e = getenv("NET_NAMING_SCHEME");
        if (e) {
                if (*e == ':') {
                        /* If prefixed with ':' the kernel cmdline takes precedence */
                        k = buffer ?: e + 1;
                } else
                        k = e; /* Otherwise the env var takes precedence */
        } else
                k = buffer;

        if (k) {
                cache = naming_scheme_from_name(k);
                if (cache)
                        return cache;
        }

        cache = naming_scheme_from_name(DEFAULT_NET_NAMING_SCHEME);
        assert(cache);

        return cache;
}

char *naming_scheme_flags_string(void) {
        _cleanup_strv_free_ char **l = NULL;
        char *joined;
        size_t i;

        for (i = 0; i < ELEMENTSOF(naming_scheme_flags); i++) {
                if (!naming_scheme_has(naming_scheme_flags[i].flag))
                        continue;

                if (strv_extend(&l, naming_scheme_flags[i].name) < 0) {
                        log_oom();
                        return NULL;
                }
        }

        joined = strv_join(l, ",");
        if (!joined)
                log_oom();

        return joined;
}
