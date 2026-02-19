/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>

#include "dissect-image.h"
#include "glyph-util.h"
#include "log.h"
#include "logs-show.h"
#include "loop-util.h"
#include "main-func.h"
#include "mount-util.h"
#include "stat-util.h"
#include "systemctl.h"
#include "systemctl-add-dependency.h"
#include "systemctl-cancel-job.h"
#include "systemctl-clean-or-freeze.h"
#include "systemctl-compat-halt.h"
#include "systemctl-daemon-reload.h"
#include "systemctl-edit.h"
#include "systemctl-enable.h"
#include "systemctl-is-active.h"
#include "systemctl-is-enabled.h"
#include "systemctl-is-system-running.h"
#include "systemctl-kill.h"
#include "systemctl-list-dependencies.h"
#include "systemctl-list-jobs.h"
#include "systemctl-list-machines.h"
#include "systemctl-list-unit-files.h"
#include "systemctl-list-units.h"
#include "systemctl-log-setting.h"
#include "systemctl-logind.h"
#include "systemctl-mount.h"
#include "systemctl-preset-all.h"
#include "systemctl-reset-failed.h"
#include "systemctl-service-watchdogs.h"
#include "systemctl-set-default.h"
#include "systemctl-set-environment.h"
#include "systemctl-set-property.h"
#include "systemctl-show.h"
#include "systemctl-start-special.h"
#include "systemctl-start-unit.h"
#include "systemctl-switch-root.h"
#include "systemctl-trivial-method.h"
#include "systemctl-util.h"
#include "systemctl-whoami.h"
#include "verbs.h"
#include "virt.h"

static int systemctl_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "list-units",            VERB_ANY, VERB_ANY, VERB_DEFAULT|VERB_ONLINE_ONLY, verb_list_units },
                { "list-unit-files",       VERB_ANY, VERB_ANY, 0,                verb_list_unit_files         },
                { "list-automounts",       VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_list_automounts         },
                { "list-paths",            VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_list_paths              },
                { "list-sockets",          VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_list_sockets            },
                { "list-timers",           VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_list_timers             },
                { "list-jobs",             VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_list_jobs               },
                { "list-machines",         VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_list_machines           },
                { "clear-jobs",            VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_trivial_method          },
                { "cancel",                VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_cancel                  },
                { "start",                 VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_start                   },
                { "stop",                  VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_start                   },
                { "condstop",              2,        VERB_ANY, VERB_ONLINE_ONLY, verb_start                   }, /* For compatibility with ALTLinux */
                { "reload",                2,        VERB_ANY, VERB_ONLINE_ONLY, verb_start                   },
                { "restart",               2,        VERB_ANY, VERB_ONLINE_ONLY, verb_start                   },
                { "try-restart",           2,        VERB_ANY, VERB_ONLINE_ONLY, verb_start                   },
                { "reload-or-restart",     VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_start                   },
                { "reload-or-try-restart", 2,        VERB_ANY, VERB_ONLINE_ONLY, verb_start                   }, /* For compatibility with old systemctl <= 228 */
                { "try-reload-or-restart", 2,        VERB_ANY, VERB_ONLINE_ONLY, verb_start                   },
                { "force-reload",          2,        VERB_ANY, VERB_ONLINE_ONLY, verb_start                   }, /* For compatibility with SysV */
                { "condreload",            2,        VERB_ANY, VERB_ONLINE_ONLY, verb_start                   }, /* For compatibility with ALTLinux */
                { "condrestart",           2,        VERB_ANY, VERB_ONLINE_ONLY, verb_start                   }, /* For compatibility with RH */
                { "isolate",               2,        2,        VERB_ONLINE_ONLY, verb_start                   },
                { "kill",                  2,        VERB_ANY, VERB_ONLINE_ONLY, verb_kill                    },
                { "clean",                 2,        VERB_ANY, VERB_ONLINE_ONLY, verb_clean_or_freeze         },
                { "freeze",                2,        VERB_ANY, VERB_ONLINE_ONLY, verb_clean_or_freeze         },
                { "thaw",                  2,        VERB_ANY, VERB_ONLINE_ONLY, verb_clean_or_freeze         },
                { "is-active",             2,        VERB_ANY, VERB_ONLINE_ONLY, verb_is_active               },
                { "check",                 2,        VERB_ANY, VERB_ONLINE_ONLY, verb_is_active               }, /* deprecated alias of is-active */
                { "is-failed",             VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_is_failed               },
                { "show",                  VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_show                    },
                { "cat",                   2,        VERB_ANY, VERB_ONLINE_ONLY, verb_cat                     },
                { "status",                VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_show                    },
                { "help",                  VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_show                    },
                { "daemon-reload",         1,        1,        VERB_ONLINE_ONLY, verb_daemon_reload           },
                { "daemon-reexec",         1,        1,        VERB_ONLINE_ONLY, verb_daemon_reload           },
                { "log-level",             VERB_ANY, 2,        VERB_ONLINE_ONLY, verb_log_setting             },
                { "log-target",            VERB_ANY, 2,        VERB_ONLINE_ONLY, verb_log_setting             },
                { "service-log-level",     2,        3,        VERB_ONLINE_ONLY, verb_service_log_setting     },
                { "service-log-target",    2,        3,        VERB_ONLINE_ONLY, verb_service_log_setting     },
                { "service-watchdogs",     VERB_ANY, 2,        VERB_ONLINE_ONLY, verb_service_watchdogs       },
                { "show-environment",      VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_show_environment        },
                { "set-environment",       2,        VERB_ANY, VERB_ONLINE_ONLY, verb_set_environment         },
                { "unset-environment",     2,        VERB_ANY, VERB_ONLINE_ONLY, verb_set_environment         },
                { "import-environment",    VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_import_environment      },
                { "halt",                  VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_start_system_special    },
                { "poweroff",              VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_start_system_special    },
                { "reboot",                VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_start_system_special    },
                { "kexec",                 VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_start_system_special    },
                { "soft-reboot",           VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_start_system_special    },
                { "sleep",                 VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_start_system_special    },
                { "suspend",               VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_start_system_special    },
                { "hibernate",             VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_start_system_special    },
                { "hybrid-sleep",          VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_start_system_special    },
                { "suspend-then-hibernate",VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_start_system_special    },
                { "default",               VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_start_special           },
                { "rescue",                VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_start_system_special    },
                { "emergency",             VERB_ANY, 1,        VERB_ONLINE_ONLY, verb_start_system_special    },
                { "exit",                  VERB_ANY, 2,        VERB_ONLINE_ONLY, verb_start_special           },
                { "reset-failed",          VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_reset_failed            },
                { "enable",                2,        VERB_ANY, 0,                verb_enable                  },
                { "disable",               2,        VERB_ANY, 0,                verb_enable                  },
                { "is-enabled",            2,        VERB_ANY, 0,                verb_is_enabled              },
                { "reenable",              2,        VERB_ANY, 0,                verb_enable                  },
                { "preset",                2,        VERB_ANY, 0,                verb_enable                  },
                { "preset-all",            VERB_ANY, 1,        0,                verb_preset_all              },
                { "mask",                  2,        VERB_ANY, 0,                verb_enable                  },
                { "unmask",                2,        VERB_ANY, 0,                verb_enable                  },
                { "link",                  2,        VERB_ANY, 0,                verb_enable                  },
                { "revert",                2,        VERB_ANY, 0,                verb_enable                  },
                { "switch-root",           VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_switch_root             },
                { "list-dependencies",     VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_list_dependencies       },
                { "set-default",           2,        2,        0,                verb_set_default             },
                { "get-default",           VERB_ANY, 1,        0,                verb_get_default             },
                { "set-property",          3,        VERB_ANY, VERB_ONLINE_ONLY, verb_set_property            },
                { "is-system-running",     VERB_ANY, 1,        0,                verb_is_system_running       },
                { "add-wants",             3,        VERB_ANY, 0,                verb_add_dependency          },
                { "add-requires",          3,        VERB_ANY, 0,                verb_add_dependency          },
                { "edit",                  2,        VERB_ANY, VERB_ONLINE_ONLY, verb_edit                    },
                { "bind",                  3,        4,        VERB_ONLINE_ONLY, verb_bind                    },
                { "mount-image",           4,        5,        VERB_ONLINE_ONLY, verb_mount_image             },
                { "whoami",                VERB_ANY, VERB_ANY, VERB_ONLINE_ONLY, verb_whoami                  },
                {}
        };

        const Verb *verb = verbs_find_verb(argv[optind], verbs);
        if (verb && (verb->flags & VERB_ONLINE_ONLY) && arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Verb '%s' cannot be used with --root= or --image=.",
                                       argv[optind] ?: verb->verb);

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        int r;

        setlocale(LC_ALL, "");
        log_setup();

        r = systemctl_dispatch_parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        journal_browse_prepare();

        if (proc_mounted() == 0)
                log_full(arg_no_warn ? LOG_DEBUG : LOG_WARNING,
                         "%s%s/proc/ is not mounted. This is not a supported mode of operation. Please fix\n"
                         "your invocation environment to mount /proc/ and /sys/ properly. Proceeding anyway.\n"
                         "Your mileage may vary.",
                         optional_glyph(GLYPH_WARNING_SIGN),
                         optional_glyph(GLYPH_SPACE));

        if (arg_action != ACTION_SYSTEMCTL && running_in_chroot() > 0) {
                if (!arg_quiet)
                        log_info("Running in chroot, ignoring request.");
                r = 0;
                goto finish;
        }

        /* systemctl_main() will print an error message for the bus connection, but only if it needs to */

        if (arg_image) {
                assert(!arg_root);

                r = mount_image_privately_interactively(
                                arg_image,
                                arg_image_policy,
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_RELAX_VAR_CHECK |
                                DISSECT_IMAGE_VALIDATE_OS |
                                DISSECT_IMAGE_ALLOW_USERSPACE_VERITY,
                                &mounted_dir,
                                /* ret_dir_fd= */ NULL,
                                &loop_device);
                if (r < 0)
                        return r;

                arg_root = strdup(mounted_dir);
                if (!arg_root)
                        return log_oom();
        }

        switch (arg_action) {

        case ACTION_SYSTEMCTL:
                r = systemctl_main(argc, argv);
                break;

        /* Legacy command aliases set arg_action. They provide some fallbacks, e.g. to tell sysvinit to
         * reboot after you have installed systemd binaries. */

        case ACTION_HALT:
        case ACTION_POWEROFF:
        case ACTION_REBOOT:
        case ACTION_KEXEC:
                r = halt_main();
                break;

        case ACTION_CANCEL_SHUTDOWN:
                r = logind_cancel_shutdown();
                break;

        case ACTION_SHOW_SHUTDOWN:
        case ACTION_SYSTEMCTL_SHOW_SHUTDOWN:
                r = logind_show_shutdown();
                break;

        case ACTION_RESCUE:
        case ACTION_RELOAD:
        case ACTION_REEXEC:
        case ACTION_EXIT:
        case ACTION_SLEEP:
        case ACTION_SUSPEND:
        case ACTION_HIBERNATE:
        case ACTION_HYBRID_SLEEP:
        case ACTION_SUSPEND_THEN_HIBERNATE:
        case ACTION_EMERGENCY:
        case ACTION_DEFAULT:
                /* systemctl verbs with no equivalent in the legacy commands. These cannot appear in
                 * arg_action. Fall through. */

        case _ACTION_INVALID:
        default:
                assert_not_reached();
        }

finish:
        release_busses();

        /* Note that we return r here, not 0, so that we can implement the LSB-like return codes */
        return r;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
