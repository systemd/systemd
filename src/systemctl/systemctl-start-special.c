/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootspec.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "efivars.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "reboot-util.h"
#include "systemctl-logind.h"
#include "systemctl-start-special.h"
#include "systemctl-start-unit.h"
#include "systemctl-trivial-method.h"
#include "systemctl-util.h"
#include "systemctl.h"

static int load_kexec_kernel(void) {
        _cleanup_(boot_config_free) BootConfig config = {};
        _cleanup_free_ char *kernel = NULL, *initrd = NULL, *options = NULL;
        const BootEntry *e;
        pid_t pid;
        int r;

        if (kexec_loaded()) {
                log_debug("Kexec kernel already loaded.");
                return 0;
        }

        if (access(KEXEC, X_OK) < 0)
                return log_error_errno(errno, KEXEC" is not available: %m");

        r = boot_entries_load_config_auto(NULL, NULL, &config);
        if (r == -ENOKEY)
                /* The call doesn't log about ENOKEY, let's do so here. */
                return log_error_errno(r,
                                       "No kexec kernel loaded and autodetection failed.\n%s",
                                       is_efi_boot()
                                       ? "Cannot automatically load kernel: ESP partition mount point not found."
                                       : "Automatic loading works only on systems booted with EFI.");
        if (r < 0)
                return r;

        e = boot_config_default_entry(&config);
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "No boot loader entry suitable as default, refusing to guess.");

        log_debug("Found default boot loader entry in file \"%s\"", e->path);

        if (!e->kernel)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Boot entry does not refer to Linux kernel, which is not supported currently.");
        if (strv_length(e->initrd) > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Boot entry specifies multiple initrds, which is not supported currently.");

        kernel = path_join(e->root, e->kernel);
        if (!kernel)
                return log_oom();

        if (!strv_isempty(e->initrd)) {
                initrd = path_join(e->root, e->initrd[0]);
                if (!initrd)
                        return log_oom();
        }

        options = strv_join(e->options, " ");
        if (!options)
                return log_oom();

        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                 "%s "KEXEC" --load \"%s\" --append \"%s\"%s%s%s",
                 arg_dry_run ? "Would run" : "Running",
                 kernel,
                 options,
                 initrd ? " --initrd \"" : NULL, strempty(initrd), initrd ? "\"" : "");
        if (arg_dry_run)
                return 0;

        r = safe_fork("(kexec)", FORK_WAIT|FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                const char* const args[] = {
                        KEXEC,
                        "--load", kernel,
                        "--append", options,
                        initrd ? "--initrd" : NULL, initrd,
                        NULL
                };

                /* Child */
                execv(args[0], (char * const *) args);
                _exit(EXIT_FAILURE);
        }

        return 0;
}

static int set_exit_code(uint8_t code) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_systemd_mgr, "SetExitCode", &error, NULL, "y", code);
        if (r < 0)
                return log_error_errno(r, "Failed to set exit code: %s", bus_error_message(&error, r));

        return 0;
}

int start_special(int argc, char *argv[], void *userdata) {
        bool termination_action; /* An action that terminates the manager, can be performed also by
                                  * signal. */
        enum action a;
        int r;

        assert(argv);

        a = verb_to_action(argv[0]);

        r = logind_check_inhibitors(a);
        if (r < 0)
                return r;

        if (arg_force >= 2) {
                r = must_be_root();
                if (r < 0)
                        return r;
        }

        r = prepare_firmware_setup();
        if (r < 0)
                return r;

        r = prepare_boot_loader_menu();
        if (r < 0)
                return r;

        r = prepare_boot_loader_entry();
        if (r < 0)
                return r;

        if (a == ACTION_REBOOT) {
                const char *arg = NULL;

                if (argc > 1) {
                        if (arg_reboot_argument)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Both --reboot-argument= and positional argument passed to reboot command, refusing.");

                        log_notice("Positional argument to reboot command is deprecated, please use --reboot-argument= instead. Accepting anyway.");
                        arg = argv[1];
                } else
                        arg = arg_reboot_argument;

                if (arg) {
                        r = update_reboot_parameter_and_warn(arg, false);
                        if (r < 0)
                                return r;
                }

        } else if (a == ACTION_KEXEC) {
                r = load_kexec_kernel();
                if (r < 0 && arg_force >= 1)
                        log_notice("Failed to load kexec kernel, continuing without.");
                else if (r < 0)
                        return r;

        } else if (a == ACTION_EXIT && argc > 1) {
                uint8_t code;

                /* If the exit code is not given on the command line, don't reset it to zero: just keep it as
                 * it might have been set previously. */

                r = safe_atou8(argv[1], &code);
                if (r < 0)
                        return log_error_errno(r, "Invalid exit code.");

                r = set_exit_code(code);
                if (r < 0)
                        return r;
        }

        termination_action = IN_SET(a,
                                    ACTION_HALT,
                                    ACTION_POWEROFF,
                                    ACTION_REBOOT);
        if (termination_action && arg_force >= 2)
                return halt_now(a);

        if (arg_force >= 1 &&
            (termination_action || IN_SET(a, ACTION_KEXEC, ACTION_EXIT)))
                r = trivial_method(argc, argv, userdata);
        else {
                /* First try logind, to allow authentication with polkit */
                if (IN_SET(a,
                           ACTION_POWEROFF,
                           ACTION_REBOOT,
                           ACTION_HALT,
                           ACTION_SUSPEND,
                           ACTION_HIBERNATE,
                           ACTION_HYBRID_SLEEP,
                           ACTION_SUSPEND_THEN_HIBERNATE)) {

                        r = logind_reboot(a);
                        if (r >= 0)
                                return r;
                        if (IN_SET(r, -EOPNOTSUPP, -EINPROGRESS))
                                /* Requested operation is not supported or already in progress */
                                return r;

                        /* On all other errors, try low-level operation. In order to minimize the difference
                         * between operation with and without logind, we explicitly enable non-blocking mode
                         * for this, as logind's shutdown operations are always non-blocking. */

                        arg_no_block = true;

                } else if (IN_SET(a, ACTION_EXIT, ACTION_KEXEC))
                        /* Since exit/kexec are so close in behaviour to power-off/reboot, let's also make
                         * them asynchronous, in order to not confuse the user needlessly with unexpected
                         * behaviour. */
                        arg_no_block = true;

                r = start_unit(argc, argv, userdata);
        }

        if (termination_action && arg_force < 2 &&
            IN_SET(r, -ENOENT, -ETIMEDOUT))
                log_notice("It is possible to perform action directly, see discussion of --force --force in man:systemctl(1).");

        return r;
}

int start_system_special(int argc, char *argv[], void *userdata) {
        /* Like start_special above, but raises an error when running in user mode */

        if (arg_scope != UNIT_FILE_SYSTEM)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Bad action for %s mode.",
                                       arg_scope == UNIT_FILE_GLOBAL ? "--global" : "--user");

        return start_special(argc, argv, userdata);
}
