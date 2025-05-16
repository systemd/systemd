/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "efivars.h"
#include "env-util.h"
#include "factory-reset.h"
#include "log.h"
#include "os-util.h"
#include "proc-cmdline.h"
#include "string-table.h"

static bool factory_reset_supported(void) {
        int r;

        r = secure_getenv_bool("SYSTEMD_FACTORY_RESET_SUPPORTED");
        if (r >= 0)
                return r;
        if (r != -ENXIO)
                log_debug_errno(r, "Unable to parse $SYSTEMD_FACTORY_RESET_SUPPORTED, ignoring: %m");

        return true;
}

static FactoryResetMode factory_reset_mode_efi_variable(void) {
        int r;

        if (!is_efi_boot()) {
                log_debug("Not booted in EFI mode, not checking FactoryResetRequest variable.");
                return FACTORY_RESET_UNSPECIFIED;
        }

        _cleanup_free_ char *req_str = NULL;
        r = efi_get_variable_string(EFI_SYSTEMD_VARIABLE_STR("FactoryResetRequest"), &req_str);
        if (r == -ENOENT) {
                log_debug_errno(r, "EFI variable FactoryResetRequest is not set, skipping.");
                return FACTORY_RESET_UNSPECIFIED;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to get EFI variable FactoryResetRequest: %m");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = sd_json_parse(req_str, /* flags= */ 0, &v, /* reterr_line= */ NULL, /* ret_column= */ NULL);
        if (r < 0) {
                log_debug_errno(r, "EFI variable FactoryResetRequest set to invalid JSON, ignoring: %m");
                return FACTORY_RESET_UNSPECIFIED;
        }

        struct {
                const char *id;
                const char *image_id;
                sd_id128_t boot_id;
        } req = {};
        static const sd_json_dispatch_field dispatch_table[] = {
                { "osReleaseId",      SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(req, id),       SD_JSON_MANDATORY },
                { "osReleaseImageId", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(req, image_id), 0                 },
                { "bootId",           SD_JSON_VARIANT_STRING, sd_json_dispatch_id128,        voffsetof(req, boot_id),  SD_JSON_MANDATORY },
                {},
        };

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &req);
        if (r < 0) {
                log_debug_errno(r, "Unable to dispatch EFI variable FactoryResetRequest, ignoring: %m");
                return FACTORY_RESET_UNSPECIFIED;
        }

        _cleanup_free_ char *id = NULL, *image_id = NULL;
        r = parse_os_release(
                        /* root= */ NULL,
                        "ID", &id,
                        "IMAGE_ID", &image_id);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse os-release: %m");

        if (!streq_ptr(req.id, id) || !streq_ptr(req.image_id, image_id)) {
                log_debug("FactoryResetRequest EFI variable set, but not for us, ignoring.");
                return FACTORY_RESET_UNSPECIFIED;
        }

        sd_id128_t boot_id;
        r = sd_id128_get_boot(&boot_id);
        if (r < 0)
                return log_debug_errno(r, "Failed to query boot ID: %m");

        if (sd_id128_equal(req.boot_id, boot_id)) {
                /* NB: if the boot ID in the EFI variable matches our *current* one, then the request is not
                 * intended for us, but for the *next* boot. */
                log_debug("EFI variable FactoryResetRequest set for next boot.");
                return FACTORY_RESET_PENDING;
        }

        return FACTORY_RESET_ON;
}

FactoryResetMode factory_reset_mode(void) {
        int r;

        if (!factory_reset_supported())
                return FACTORY_RESET_UNSUPPORTED;

        /* First check if we already completed a factory reset in this boot */
        if (access("/run/systemd/factory-reset-complete", F_OK) >= 0)
                return FACTORY_RESET_COMPLETE;
        if (errno != ENOENT)
                return log_debug_errno(errno, "Can't determine if /run/systemd/factory-reset-complete exists: %m");

        bool b;
        r = proc_cmdline_get_bool("systemd.factory_reset", /* flags= */ 0, &b);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse systemd.factory_reset kernel command line argument: %m");
        if (r == 0)  /* Check EFI variable in case kernel cmdline switch is not specified */
                return factory_reset_mode_efi_variable();

        return b ? FACTORY_RESET_ON : FACTORY_RESET_OFF; /* Honour if explicitly turned off or on via kernel cmdline */
}

static const char* const factory_reset_mode_table[_FACTORY_RESET_MODE_MAX] = {
        [FACTORY_RESET_UNSUPPORTED] = "unsupported",
        [FACTORY_RESET_UNSPECIFIED] = "unspecified",
        [FACTORY_RESET_OFF]         = "off",
        [FACTORY_RESET_ON]          = "on",
        [FACTORY_RESET_COMPLETE]    = "complete",
        [FACTORY_RESET_PENDING]     = "pending",
};

DEFINE_STRING_TABLE_LOOKUP(factory_reset_mode, FactoryResetMode);
