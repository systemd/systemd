/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-hwdb.h"

#include "dropin.h"
#include "fileio.h"
#include "generator.h"
#include "imds-util.h"
#include "log.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "special.h"
#include "string-util.h"
#include "virt.h"

static int arg_enabled = -1;           /* Whether we shall offer local IMDS APIs */
static bool arg_import = true;         /* Whether we shall import IMDS credentials, SSH keys, … into the local system */
static ImdsNetworkMode arg_network_mode = IMDS_NETWORK_DEFAULT;

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        assert(key);

        if (proc_cmdline_key_streq(key, "systemd.imds")) {
                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = parse_tristate_full(value, "auto", &arg_enabled);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse systemd.imds= value: %m");

        } else if (proc_cmdline_key_streq(key, "systemd.imds.import")) {
                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = parse_boolean(value);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse systemd.imds.import= value: %m");

                arg_import = r;
        } else if (proc_cmdline_key_streq(key, "systemd.imds.network")) {
                if (proc_cmdline_value_missing(key, value))
                        return 0;

                ImdsNetworkMode m = imds_network_mode_from_string(value);
                if (m < 0)
                        return log_warning_errno(m, "Failed to parse systemd.imds.network= value: %m");

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

        /* To detect Azure we need to check the chassis asset tag. Unfortunately the kernel does not include
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
         * ask udev for this, as we typically run long before udev. Hence we'll do the hwdb lookup via
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

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r;

        r = proc_cmdline_parse(parse_proc_cmdline_item, /* userdata= */ NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        if (arg_enabled < 0) {
                Virtualization v = detect_container();
                if (v < 0)
                        log_debug_errno(v, "Container detection failed, ignoring: %m");
                if (v > 0) {
                        log_debug("Running in a container, disabling IMDS logic.");
                        arg_enabled = false;
                } else {
                        r = smbios_query();
                        if (r < 0)
                                return r;
                        arg_enabled = r > 0;
                }
        }

        if (!arg_enabled) {
                log_debug("IMDS not enabled, skipping generator.");
                return 0;
        }

        log_info("IMDS support enabled, pulling in IMDS units.");

        /* Enable IMDS early networking, so that we can actually reach the IMDS server. */
        if (arg_network_mode != IMDS_NETWORK_OFF) {
                r = generator_add_symlink(dest_early, SPECIAL_SYSINIT_TARGET, "wants", SYSTEM_DATA_UNIT_DIR "/systemd-imds-early-network.service");
                if (r < 0)
                        return log_error_errno(r, "Failed to hook in systemd-imds-early-network.service: %m");
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
