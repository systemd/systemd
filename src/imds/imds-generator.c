/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-hwdb.h"

#include "dropin.h"
#include "fileio.h"
#include "generator.h"
#include "log.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "special.h"
#include "string-table.h"
#include "string-util.h"

typedef enum NetworkMode {
        NETWORK_OFF,                /* No automatic pre-IMDS network configuration, something else has to do this. (Also: no "prohibit" route) */
        NETWORK_LOCKED,             /* "Prohibit" route for the IMDS server, unless you have SO_MARK set to 0x7FFF0815 */
        NETWORK_UNLOCKED,           /* No "prohibit" route for the IMDS server */
        _NETWORK_MODE_MAX,
        _NETWORK_MODE_INVALID = -EINVAL,
} NetworkMode;

static int arg_enabled = -1;           /* Whether we shall offer local IMDS APIs */
static bool arg_import = true;         /* Whether we shall import IMDS credentials, SSH keys, … into the local system */
static NetworkMode arg_network_mode = NETWORK_LOCKED;

static const char * const network_mode_table[_NETWORK_MODE_MAX] = {
        [NETWORK_OFF]      = "off",
        [NETWORK_LOCKED]   = "locked",
        [NETWORK_UNLOCKED] = "unlocked",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(network_mode, NetworkMode, NETWORK_LOCKED);

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        assert(key);

        if (streq(key, "systemd.imds")) {
                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = parse_tristate_full(value, "auto", &arg_enabled);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse systemd.idms= value: %m");

        } else if (streq(key, "systemd.imds.import")) {
                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = parse_boolean(value);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse systemd.idms.import= value: %m");

                arg_import = r;
        } else if (streq(key, "systemd.imds.network")) {
                if (proc_cmdline_value_missing(key, value))
                        return 0;

                NetworkMode m = network_mode_from_string(value);
                if (m < 0)
                        return log_warning_errno(m, "Failed to parse systemd.idms.network= value: %m");

                arg_network_mode = m;
        }

        return 0;
}

static int smbios_get_modalias(char **ret) {
        int r;

        assert(ret);

        _cleanup_free_ char *modalias = NULL;
        r = read_virtual_file("/sys/devices/virtual/dmi/id/modalias", SIZE_MAX, &modalias, /* ret_size= */ NULL);
        if (r < 0)
                return r;

        truncate_nl(modalias);

        /* To detect Azure we need to check the chassis assert tag. Unfortunately the kernel does not include
         * it in the modalias string right now. Let's hence append it manually. This matches similar logic in
         * rules.d/60-dmi-id.rules. */
        _cleanup_free_ char *cat = NULL;
        r = read_virtual_file("/sys/devices/virtual/dmi/id/chassis_asset_tag", SIZE_MAX, &cat, /* ret_size= */ NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read chassis asset tag, ignoring: %m");
        else {
                truncate_nl(cat);

                if (!string_has_cc(cat, /* ok= */ NULL) && !isempty(cat) && !strextend(&modalias, "cat", cat, ":"))
                        return -ENOMEM;
        }

        log_debug("Constructed SMBIOS modalias string: %s", modalias);
        *ret = TAKE_PTR(modalias);
        return 0;
}

static int smbios_query(void) {
        int r;

        /* Let's check whether the DMI device's hwdb data suggests IMDS support is available. Note, we cannot
         * ask udev for this, before we typically run long before udev. Hence we'll do the hwdb lookup via
         * sd-hwdb directly. */

        _cleanup_free_ char *modalias = NULL;
        r = smbios_get_modalias(&modalias);
        if (r == -ENOENT) {
                log_debug("No DMI device found, assuming IMDS is not available.");
                return false;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read DMI modalias: %m");

        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        r = sd_hwdb_new(&hwdb);
        if (r < 0)
                return log_error_errno(r, "Failed to open hwdb: %m");

        r = sd_hwdb_seek(hwdb, modalias);
        if (r == -ENOENT) {
                log_debug("No hwdb data for DMI device found, assuming IMDS is off.");
                return false;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to seek in hwdb for '%s': %m", modalias);

        for (;;) {
                const char *key, *value;
                r = sd_hwdb_enumerate(hwdb, &key, &value);
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate hwdb entry for '%s': %m", modalias);
                if (r == 0)
                        break;

                if (streq(key, "IMDS_VENDOR"))
                        return true;
        }

        log_debug("IMDS_VENDOR= property for DMI device not set, assuming IMDS is not available.");
        return false;
}

static const char *network_service(void) {
        switch (arg_network_mode) {

        case NETWORK_LOCKED:
                return "systemd-imds-early-network.service";

        case NETWORK_UNLOCKED:
                return "systemd-imds-early-network-unlocked.service";

        case NETWORK_OFF:
                return NULL;

        default:
                assert_not_reached();
        }
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r;

        r = proc_cmdline_parse(parse_proc_cmdline_item, /* userdata= */ NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        if (arg_enabled < 0) {
                r = smbios_query();
                if (r < 0)
                        return r;

                arg_enabled = r > 0;
        }

        if (!arg_enabled) {
                log_debug("IMDS not enabled, skipping generator.");
                return 0;
        }

        log_info("IMDS support enabled, activating support.");

        /* Enable IMDS early networking, so that we can actually reach the IMDS server. */
        const char *unit = network_service();
        if (unit) {
                _cleanup_free_ char *p = path_join(SYSTEM_DATA_UNIT_DIR, unit);
                if (!p)
                        return log_oom();

                r = generator_add_symlink(dest_early, SPECIAL_SYSINIT_TARGET, "wants", p);
                if (r < 0)
                        return log_error_errno(r, "Failed to hook in unit: %m");
        }

        /* Enable the IMDS service socket */
        r = generator_add_symlink(dest_early, SPECIAL_SOCKETS_TARGET, "wants", SYSTEM_DATA_UNIT_DIR "/systemd-imdsd.socket");
        if (r < 0)
                return log_error_errno(r, "Failed to hook in systemd-imdsd.socket: %m");

        /* We now know the SMBIOS device exists, hence it's safe now to order the IMDS service after it, so
         * that it has all properties properly initialized. */
        r = write_drop_in(
                        dest_early,
                        "systemd-imdsd@.service",
                        50, "dmi-id",
                        "# Automatically generated by systemd-imds-generator\n\n"
                        "[Unit]\n"
                        "Wants=sys-devices-virtual-dmi-id.device\n"
                        "After=sys-devices-virtual-dmi-id.device\n");
        if (r < 0)
                return log_error_errno(r, "Failed to hook DMI id device before systemd-imdsd@.service: %m");

        if (arg_import) {
                /* Enable that we import IMDS data */
                r = generator_add_symlink(dest_early, SPECIAL_SYSINIT_TARGET, "wants", SYSTEM_DATA_UNIT_DIR "/systemd-imds-import.service");
                if (r < 0)
                        return log_error_errno(r, "Failed to hook in systemd-imds-import.service: %m");
        }

        return 0;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
