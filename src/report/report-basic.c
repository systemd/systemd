/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/utsname.h>

#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "architecture.h"
#include "facts.h"
#include "hostname-setup.h"
#include "report-basic.h"
#include "virt.h"

static int architecture_generate(FactFamilyContext *context, void *userdata) {
        assert(context);

        return fact_build_send_string(
                        context,
                        /* object= */ NULL,
                        architecture_to_string(uname_architecture()));
}

static int boot_id_generate(FactFamilyContext *context, void *userdata) {
        sd_id128_t id;
        int r;

        assert(context);

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return r;

        return fact_build_send_string(
                        context,
                        /* object= */ NULL,
                        SD_ID128_TO_STRING(id));
}

static int hostname_generate(FactFamilyContext *context, void *userdata) {
        _cleanup_free_ char *hostname = NULL;
        int r;

        assert(context);

        r = gethostname_full(GET_HOSTNAME_ALLOW_LOCALHOST | GET_HOSTNAME_FALLBACK_DEFAULT, &hostname);
        if (r < 0)
                return r;

        return fact_build_send_string(
                        context,
                        /* object= */ NULL,
                        hostname);
}

static int kernel_version_generate(FactFamilyContext *context, void *userdata) {
        struct utsname u;

        assert(context);

        assert_se(uname(&u) >= 0);

        return fact_build_send_string(
                        context,
                        /* object= */ NULL,
                        u.release);
}

static int machine_id_generate(FactFamilyContext *context, void *userdata) {
        sd_id128_t id;
        int r;

        assert(context);

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return r;

        return fact_build_send_string(
                        context,
                        /* object= */ NULL,
                        SD_ID128_TO_STRING(id));
}

static int virtualization_generate(FactFamilyContext *context, void *userdata) {
        Virtualization v;

        assert(context);

        v = detect_virtualization();
        if (v < 0)
                return v;

        return fact_build_send_string(
                        context,
                        /* object= */ NULL,
                        virtualization_to_string(v));
}

static const FactFamily fact_family_table[] = {
        /* Keep facts ordered alphabetically */
        {
                .name = FACT_IO_SYSTEMD_BASIC "Architecture",
                .description = "CPU architecture",
                .generate = architecture_generate,
        },
        {
                .name = FACT_IO_SYSTEMD_BASIC "BootID",
                .description = "Current boot ID",
                .generate = boot_id_generate,
        },
        {
                .name = FACT_IO_SYSTEMD_BASIC "Hostname",
                .description = "System hostname",
                .generate = hostname_generate,
        },
        {
                .name = FACT_IO_SYSTEMD_BASIC "KernelVersion",
                .description = "Kernel version",
                .generate = kernel_version_generate,
        },
        {
                .name = FACT_IO_SYSTEMD_BASIC "MachineID",
                .description = "Machine ID",
                .generate = machine_id_generate,
        },
        {
                .name = FACT_IO_SYSTEMD_BASIC "Virtualization",
                .description = "Virtualization type",
                .generate = virtualization_generate,
        },
        {}
};

int vl_method_describe_facts(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return facts_method_describe(fact_family_table, link, parameters, flags, userdata);
}

int vl_method_list_facts(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return facts_method_list(fact_family_table, link, parameters, flags, userdata);
}
