/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/utsname.h>

#include "sd-id128.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "architecture.h"
#include "hostname-setup.h"
#include "report-facts.h"
#include "virt.h"

typedef struct LocalFact {
        const char *name;
        const char *description;
        int (*generate)(sd_json_variant **ret);
} LocalFact;

static int architecture_generate(sd_json_variant **ret) {
        return sd_json_variant_new_string(ret, architecture_to_string(uname_architecture()));
}

static int boot_id_generate(sd_json_variant **ret) {
        sd_id128_t id;
        int r;

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return r;

        return sd_json_variant_new_string(ret, SD_ID128_TO_STRING(id));
}

static int hostname_generate(sd_json_variant **ret) {
        _cleanup_free_ char *hostname = NULL;
        int r;

        r = gethostname_full(GET_HOSTNAME_ALLOW_LOCALHOST | GET_HOSTNAME_FALLBACK_DEFAULT, &hostname);
        if (r < 0)
                return r;

        return sd_json_variant_new_string(ret, hostname);
}

static int kernel_version_generate(sd_json_variant **ret) {
        struct utsname u;

        assert_se(uname(&u) >= 0);

        return sd_json_variant_new_string(ret, u.release);
}

static int machine_id_generate(sd_json_variant **ret) {
        sd_id128_t id;
        int r;

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return r;

        return sd_json_variant_new_string(ret, SD_ID128_TO_STRING(id));
}

static int virtualization_generate(sd_json_variant **ret) {
        Virtualization v;

        v = detect_virtualization();
        if (v < 0)
                return v;

        return sd_json_variant_new_string(ret, virtualization_to_string(v));
}

static const LocalFact local_facts[] = {
        /* Keep facts ordered alphabetically */
        { FACT_PREFIX "Architecture",   "CPU architecture",    architecture_generate   },
        { FACT_PREFIX "BootID",         "Current boot ID",     boot_id_generate        },
        { FACT_PREFIX "Hostname",       "System hostname",     hostname_generate       },
        { FACT_PREFIX "KernelVersion",  "Kernel version",      kernel_version_generate },
        { FACT_PREFIX "MachineID",      "Machine ID",          machine_id_generate     },
        { FACT_PREFIX "Virtualization", "Virtualization type",  virtualization_generate },
        {}
};

int local_facts_list(sd_json_variant ***ret, size_t *ret_n) {
        _cleanup_free_ sd_json_variant **facts = NULL;
        size_t n = 0;
        int r;

        assert(ret);
        assert(ret_n);

        for (const LocalFact *f = local_facts; f->name; f++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *value = NULL;

                r = f->generate(&value);
                if (r < 0)
                        return r;

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;
                r = sd_json_buildo(
                                &entry,
                                SD_JSON_BUILD_PAIR_STRING("name", f->name),
                                SD_JSON_BUILD_PAIR("value", SD_JSON_BUILD_VARIANT(value)));
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC(facts, n + 1))
                        return -ENOMEM;

                facts[n++] = TAKE_PTR(entry);
        }

        *ret = TAKE_PTR(facts);
        *ret_n = n;
        return 0;
}

int local_facts_describe(sd_json_variant ***ret, size_t *ret_n) {
        _cleanup_free_ sd_json_variant **facts = NULL;
        size_t n = 0;
        int r;

        assert(ret);
        assert(ret_n);

        for (const LocalFact *f = local_facts; f->name; f++) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *entry = NULL;

                r = sd_json_buildo(
                                &entry,
                                SD_JSON_BUILD_PAIR_STRING("name", f->name),
                                SD_JSON_BUILD_PAIR_STRING("description", f->description));
                if (r < 0)
                        return r;

                if (!GREEDY_REALLOC(facts, n + 1))
                        return -ENOMEM;

                facts[n++] = TAKE_PTR(entry);
        }

        *ret = TAKE_PTR(facts);
        *ret_n = n;
        return 0;
}
