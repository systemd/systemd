/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "generator.h"
#include "proc-cmdline.h"
#include "special.h"
#include "tpm2-util.h"
#include "parse-util.h"

/* A small generator that enqueues tpm2.target as synchronization point if the TPM2 device hasn't shown up
 * yet, but the firmware reports it to exist. This is supposed to deal with systems where the TPM2 driver
 * support is built as kmod and must be loaded before it's ready to be used. The tpm2.target is only enqueued
 * if firmware says there is a TPM2 device, our userspace support for TPM2 is fully available but the TPM2
 * device hasn't shown up in /dev/ yet. */

static const char *arg_dest = NULL;
static int arg_tpm2_wait = -1; /* tri-state: negative → don't know */

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        assert(key);

        if (proc_cmdline_key_streq(key, "systemd.tpm2-wait")) {
                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning_errno(r, "Failed to parse 'systemd.tpm2wait' kernel command line argument, ignoring: %s", value);
                else
                        arg_tpm2_wait = r;
        }

        return 0;
}

static int generate_tpm_target_symlink(void) {
        int r;

        if (arg_tpm2_wait < 0) {
                Tpm2Support support = tpm2_support();

                if (FLAGS_SET(support, TPM2_SUPPORT_DRIVER)) {
                        log_debug("Not generating tpm2.target synchronization point, as TPM2 device is already present.");
                        return 0;
                }

                if (!FLAGS_SET(support, TPM2_SUPPORT_FIRMWARE)) {
                        log_debug("Not generating tpm2.target synchronization point, as firmware reports no TPM2 present.");
                        return 0;
                }

                if (!FLAGS_SET(support, TPM2_SUPPORT_SYSTEM|TPM2_SUPPORT_SUBSYSTEM|TPM2_SUPPORT_LIBRARIES)) {
                        log_debug("Not generating tpm2.target synchronization point, as userspace support for TPM2 is not complete.");
                        return 0;
                }
        }

        r = generator_add_symlink(arg_dest, SPECIAL_SYSINIT_TARGET, "wants", SYSTEM_DATA_UNIT_DIR "/" SPECIAL_TPM2_TARGET);
        if (r < 0)
                return log_error_errno(r, "Failed to hook in tpm2.target: %m");

        return 0;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r;

        assert_se(arg_dest = dest);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, PROC_CMDLINE_STRIP_RD_PREFIX);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        return generate_tpm_target_symlink();
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
