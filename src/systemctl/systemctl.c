/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include "argv-util.h"
#include "build.h"
#include "bus-print-properties.h"
#include "bus-util.h"
#include "capsule-util.h"
#include "extract-word.h"
#include "image-policy.h"
#include "install.h"
#include "output-mode.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "static-destruct.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "systemctl.h"
#include "systemctl-compat-halt.h"
#include "systemctl-compat-shutdown.h"
#include "systemctl-logind.h"
#include "time-util.h"

char **arg_types = NULL;
char **arg_states = NULL;
char **arg_properties = NULL;
bool arg_all = false;
enum dependency arg_dependency = DEPENDENCY_FORWARD;
const char *_arg_job_mode = NULL;
RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
bool arg_wait = false;
bool arg_no_block = false;
int arg_legend = -1; /* -1: true, unless --quiet is passed, 1: true */
PagerFlags arg_pager_flags = 0;
bool arg_no_wtmp = false;
bool arg_no_sync = false;
bool arg_no_wall = false;
bool arg_no_reload = false;
BusPrintPropertyFlags arg_print_flags = 0;
bool arg_show_types = false;
int arg_check_inhibitors = -1;
bool arg_dry_run = false;
bool arg_quiet = false;
bool arg_verbose = false;
bool arg_no_warn = false;
bool arg_full = false;
bool arg_recursive = false;
bool arg_with_dependencies = false;
bool arg_show_transaction = false;
int arg_force = 0;
bool arg_ask_password = false;
bool arg_runtime = false;
UnitFilePresetMode arg_preset_mode = UNIT_FILE_PRESET_FULL;
char **arg_wall = NULL;
const char *arg_kill_whom = NULL;
int arg_signal = SIGTERM;
int arg_kill_value;
bool arg_kill_value_set = false;
char *arg_root = NULL;
char *arg_image = NULL;
usec_t arg_when = 0;
bool arg_stdin = false;
const char *arg_reboot_argument = NULL;
enum action arg_action = ACTION_SYSTEMCTL;
BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
const char *arg_host = NULL;
unsigned arg_lines = 10;
OutputMode arg_output = OUTPUT_SHORT;
bool arg_plain = false;
bool arg_firmware_setup = false;
usec_t arg_boot_loader_menu = USEC_INFINITY;
const char *arg_boot_loader_entry = NULL;
bool arg_now = false;
bool arg_jobs_before = false;
bool arg_jobs_after = false;
char **arg_clean_what = NULL;
TimestampStyle arg_timestamp_style = TIMESTAMP_PRETTY;
bool arg_read_only = false;
bool arg_mkdir = false;
bool arg_marked = false;
const char *arg_drop_in = NULL;
ImagePolicy *arg_image_policy = NULL;
char *arg_kill_subgroup = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_types, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_states, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_properties, strv_freep);
STATIC_DESTRUCTOR_REGISTER(_arg_job_mode, unsetp);
STATIC_DESTRUCTOR_REGISTER(arg_wall, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_kill_whom, unsetp);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_reboot_argument, unsetp);
STATIC_DESTRUCTOR_REGISTER(arg_host, unsetp);
STATIC_DESTRUCTOR_REGISTER(arg_boot_loader_entry, unsetp);
STATIC_DESTRUCTOR_REGISTER(arg_clean_what, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_drop_in, unsetp);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);
STATIC_DESTRUCTOR_REGISTER(arg_kill_subgroup, freep);

static int systemctl_help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("systemctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] COMMAND ...\n\n"
               "%5$sQuery or send control commands to the system manager.%6$s\n"
               "\n%3$sUnit Commands:%4$s\n"
               "  list-units [PATTERN...]             List units currently in memory\n"
               "  list-automounts [PATTERN...]        List automount units currently in memory,\n"
               "                                      ordered by path\n"
               "  list-paths [PATTERN...]             List path units currently in memory,\n"
               "                                      ordered by path\n"
               "  list-sockets [PATTERN...]           List socket units currently in memory,\n"
               "                                      ordered by address\n"
               "  list-timers [PATTERN...]            List timer units currently in memory,\n"
               "                                      ordered by next elapse\n"
               "  is-active PATTERN...                Check whether units are active\n"
               "  is-failed [PATTERN...]              Check whether units are failed or\n"
               "                                      system is in degraded state\n"
               "  status [PATTERN...|PID...]          Show runtime status of one or more units\n"
               "  show [PATTERN...|JOB...]            Show properties of one or more\n"
               "                                      units/jobs or the manager\n"
               "  cat PATTERN...                      Show files and drop-ins of specified units\n"
               "  help PATTERN...|PID...              Show manual for one or more units\n"
               "  list-dependencies [UNIT...]         Recursively show units which are required\n"
               "                                      or wanted by the units or by which those\n"
               "                                      units are required or wanted\n"
               "  start UNIT...                       Start (activate) one or more units\n"
               "  stop UNIT...                        Stop (deactivate) one or more units\n"
               "  reload UNIT...                      Reload one or more units\n"
               "  restart UNIT...                     Start or restart one or more units\n"
               "  try-restart UNIT...                 Restart one or more units if active\n"
               "  reload-or-restart UNIT...           Reload one or more units if possible,\n"
               "                                      otherwise start or restart\n"
               "  try-reload-or-restart UNIT...       If active, reload one or more units,\n"
               "                                      if supported, otherwise restart\n"
               "  isolate UNIT                        Start one unit and stop all others\n"
               "  kill UNIT...                        Send signal to processes of a unit\n"
               "  clean UNIT...                       Clean runtime, cache, state, logs or\n"
               "                                      configuration of unit\n"
               "  freeze PATTERN...                   Freeze execution of unit processes\n"
               "  thaw PATTERN...                     Resume execution of a frozen unit\n"
               "  set-property UNIT PROPERTY=VALUE... Sets one or more properties of a unit\n"
               "  bind UNIT PATH [PATH]               Bind-mount a path from the host into a\n"
               "                                      unit's namespace\n"
               "  mount-image UNIT PATH [PATH [OPTS]] Mount an image from the host into a\n"
               "                                      unit's namespace\n"
               "  service-log-level SERVICE [LEVEL]   Get/set logging threshold for service\n"
               "  service-log-target SERVICE [TARGET] Get/set logging target for service\n"
               "  reset-failed [PATTERN...]           Reset failed state for all, one, or more\n"
               "                                      units\n"
               "  whoami [PID...]                     Return unit caller or specified PIDs are\n"
               "                                      part of\n"
               "\n%3$sUnit File Commands:%4$s\n"
               "  list-unit-files [PATTERN...]        List installed unit files\n"
               "  enable [UNIT...|PATH...]            Enable one or more unit files\n"
               "  disable UNIT...                     Disable one or more unit files\n"
               "  reenable UNIT...                    Reenable one or more unit files\n"
               "  preset UNIT...                      Enable/disable one or more unit files\n"
               "                                      based on preset configuration\n"
               "  preset-all                          Enable/disable all unit files based on\n"
               "                                      preset configuration\n"
               "  is-enabled UNIT...                  Check whether unit files are enabled\n"
               "  mask UNIT...                        Mask one or more units\n"
               "  unmask UNIT...                      Unmask one or more units\n"
               "  link PATH...                        Link one or more units files into\n"
               "                                      the search path\n"
               "  revert UNIT...                      Revert one or more unit files to vendor\n"
               "                                      version\n"
               "  add-wants TARGET UNIT...            Add 'Wants' dependency for the target\n"
               "                                      on specified one or more units\n"
               "  add-requires TARGET UNIT...         Add 'Requires' dependency for the target\n"
               "                                      on specified one or more units\n"
               "  edit UNIT...                        Edit one or more unit files\n"
               "  get-default                         Get the name of the default target\n"
               "  set-default TARGET                  Set the default target\n"
               "\n%3$sMachine Commands:%4$s\n"
               "  list-machines [PATTERN...]          List local containers and host\n"
               "\n%3$sJob Commands:%4$s\n"
               "  list-jobs [PATTERN...]              List jobs\n"
               "  cancel [JOB...]                     Cancel all, one, or more jobs\n"
               "\n%3$sEnvironment Commands:%4$s\n"
               "  show-environment                    Dump environment\n"
               "  set-environment VARIABLE=VALUE...   Set one or more environment variables\n"
               "  unset-environment VARIABLE...       Unset one or more environment variables\n"
               "  import-environment VARIABLE...      Import all or some environment variables\n"
               "\n%3$sManager State Commands:%4$s\n"
               "  daemon-reload                       Reload systemd manager configuration\n"
               "  daemon-reexec                       Reexecute systemd manager\n"
               "  log-level [LEVEL]                   Get/set logging threshold for manager\n"
               "  log-target [TARGET]                 Get/set logging target for manager\n"
               "  service-watchdogs [BOOL]            Get/set service watchdog state\n"
               "\n%3$sSystem Commands:%4$s\n"
               "  is-system-running                   Check whether system is fully running\n"
               "  default                             Enter system default mode\n"
               "  rescue                              Enter system rescue mode\n"
               "  emergency                           Enter system emergency mode\n"
               "  halt                                Shut down and halt the system\n"
               "  poweroff                            Shut down and power-off the system\n"
               "  reboot                              Shut down and reboot the system\n"
               "  kexec                               Shut down and reboot the system with kexec\n"
               "  soft-reboot                         Shut down and reboot userspace\n"
               "  exit [EXIT_CODE]                    Request user instance or container exit\n"
               "  switch-root [ROOT [INIT]]           Change to a different root file system\n"
               "  sleep                               Put the system to sleep (through one of\n"
               "                                      the operations below)\n"
               "  suspend                             Suspend the system\n"
               "  hibernate                           Hibernate the system\n"
               "  hybrid-sleep                        Hibernate and suspend the system\n"
               "  suspend-then-hibernate              Suspend the system, wake after a period of\n"
               "                                      time, and hibernate"
               "\n%3$sOptions:%4$s\n"
               "  -h --help              Show this help\n"
               "     --version           Show package version\n"
               "     --system            Connect to system manager\n"
               "     --user              Connect to user service manager\n"
               "  -C --capsule=NAME      Connect to service manager of specified capsule\n"
               "  -H --host=[USER@]HOST  Operate on remote host\n"
               "  -M --machine=CONTAINER Operate on a local container\n"
               "  -t --type=TYPE         List units of a particular type\n"
               "     --state=STATE       List units with particular LOAD or SUB or ACTIVE state\n"
               "     --failed            Shortcut for --state=failed\n"
               "  -p --property=NAME     Show only properties by this name\n"
               "  -P NAME                Equivalent to --value --property=NAME\n"
               "  -a --all               Show all properties/all units currently in memory,\n"
               "                         including dead/empty ones. To list all units installed\n"
               "                         on the system, use 'list-unit-files' instead.\n"
               "  -l --full              Don't ellipsize unit names on output\n"
               "  -r --recursive         Show unit list of host and local containers\n"
               "     --reverse           Show reverse dependencies with 'list-dependencies'\n"
               "     --before            Show units ordered before with 'list-dependencies'\n"
               "     --after             Show units ordered after with 'list-dependencies'\n"
               "     --with-dependencies Show unit dependencies with 'status', 'cat',\n"
               "                         'list-units', and 'list-unit-files'.\n"
               "     --job-mode=MODE     Specify how to deal with already queued jobs, when\n"
               "                         queueing a new job\n"
               "  -T --show-transaction  When enqueuing a unit job, show full transaction\n"
               "     --show-types        When showing sockets, explicitly show their type\n"
               "     --value             When showing properties, only print the value\n"
               "     --check-inhibitors=MODE\n"
               "                         Whether to check inhibitors before shutting down,\n"
               "                         sleeping, or hibernating\n"
               "  -i                     Shortcut for --check-inhibitors=no\n"
               "  -s --signal=SIGNAL     Which signal to send\n"
               "     --kill-whom=WHOM    Whom to send signal to\n"
               "     --kill-value=INT    Signal value to enqueue\n"
               "     --kill-subgroup=PATH\n"
               "                         Send signal to sub-control group only\n"
               "     --what=RESOURCES    Which types of resources to remove\n"
               "     --now               Start or stop unit after enabling or disabling it\n"
               "     --dry-run           Only print what would be done\n"
               "                         Currently supported by verbs: halt, poweroff, reboot,\n"
               "                             kexec, soft-reboot, suspend, hibernate, \n"
               "                             suspend-then-hibernate, hybrid-sleep, default,\n"
               "                             rescue, emergency, and exit.\n"
               "  -q --quiet             Suppress output\n"
               "  -v --verbose           Show unit logs while executing operation\n"
               "     --no-warn           Suppress several warnings shown by default\n"
               "     --wait              For (re)start, wait until service stopped again\n"
               "                         For is-system-running, wait until startup is completed\n"
               "                         For kill, wait until service stopped\n"
               "     --no-block          Do not wait until operation finished\n"
               "     --no-wall           Don't send wall message before halt/power-off/reboot\n"
               "     --message=MESSAGE   Specify human-readable reason for system shutdown\n"
               "     --no-reload         Don't reload daemon after en-/dis-abling unit files\n"
               "     --legend=BOOL       Enable/disable the legend (column headers and hints)\n"
               "     --no-pager          Do not pipe output into a pager\n"
               "     --no-ask-password   Do not ask for system passwords\n"
               "     --global            Edit/enable/disable/mask default user unit files\n"
               "                         globally\n"
               "     --runtime           Edit/enable/disable/mask unit files temporarily until\n"
               "                         next reboot\n"
               "  -f --force             When enabling unit files, override existing symlinks\n"
               "                         When shutting down, execute action immediately\n"
               "     --preset-mode=      Apply only enable, only disable, or all presets\n"
               "     --root=PATH         Edit/enable/disable/mask unit files in the specified\n"
               "                         root directory\n"
               "     --image=PATH        Edit/enable/disable/mask unit files in the specified\n"
               "                         disk image\n"
               "     --image-policy=POLICY\n"
               "                         Specify disk image dissection policy\n"
               "  -n --lines=INTEGER     Number of journal entries to show\n"
               "  -o --output=STRING     Change journal output mode (short, short-precise,\n"
               "                             short-iso, short-iso-precise, short-full,\n"
               "                             short-monotonic, short-unix, short-delta,\n"
               "                             verbose, export, json, json-pretty, json-sse, cat)\n"
               "     --firmware-setup    Tell the firmware to show the setup menu on next boot\n"
               "     --boot-loader-menu=TIME\n"
               "                         Boot into boot loader menu on next boot\n"
               "     --boot-loader-entry=NAME\n"
               "                         Boot into a specific boot loader entry on next boot\n"
               "     --reboot-argument=ARG\n"
               "                         Specify argument string to pass to reboot()\n"
               "     --plain             Print unit dependencies as a list instead of a tree\n"
               "     --timestamp=FORMAT  Change format of printed timestamps (pretty, unix,\n"
               "                             us, utc, us+utc)\n"
               "     --read-only         Create read-only bind mount\n"
               "     --mkdir             Create directory before mounting, if missing\n"
               "     --marked            Restart/reload previously marked units\n"
               "     --drop-in=NAME      Edit unit files using the specified drop-in file name\n"
               "     --when=TIME         Schedule halt/power-off/reboot/kexec action after\n"
               "                         a certain timestamp\n"
               "     --stdin             Read new contents of edited file from stdin\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static void help_types(void) {
        if (arg_legend != 0)
                puts("Available unit types:");

        DUMP_STRING_TABLE(unit_type, UnitType, _UNIT_TYPE_MAX);
}

static void help_states(void) {
        if (arg_legend != 0)
                puts("Available unit load states:");
        DUMP_STRING_TABLE(unit_load_state, UnitLoadState, _UNIT_LOAD_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable unit active states:");
        DUMP_STRING_TABLE(unit_active_state, UnitActiveState, _UNIT_ACTIVE_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable unit file states:");
        DUMP_STRING_TABLE(unit_file_state, UnitFileState, _UNIT_FILE_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable automount unit substates:");
        DUMP_STRING_TABLE(automount_state, AutomountState, _AUTOMOUNT_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable device unit substates:");
        DUMP_STRING_TABLE(device_state, DeviceState, _DEVICE_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable mount unit substates:");
        DUMP_STRING_TABLE(mount_state, MountState, _MOUNT_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable path unit substates:");
        DUMP_STRING_TABLE(path_state, PathState, _PATH_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable scope unit substates:");
        DUMP_STRING_TABLE(scope_state, ScopeState, _SCOPE_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable service unit substates:");
        DUMP_STRING_TABLE(service_state, ServiceState, _SERVICE_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable slice unit substates:");
        DUMP_STRING_TABLE(slice_state, SliceState, _SLICE_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable socket unit substates:");
        DUMP_STRING_TABLE(socket_state, SocketState, _SOCKET_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable swap unit substates:");
        DUMP_STRING_TABLE(swap_state, SwapState, _SWAP_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable target unit substates:");
        DUMP_STRING_TABLE(target_state, TargetState, _TARGET_STATE_MAX);

        if (arg_legend != 0)
                puts("\nAvailable timer unit substates:");
        DUMP_STRING_TABLE(timer_state, TimerState, _TIMER_STATE_MAX);
}

static int systemctl_parse_argv(int argc, char *argv[]) {
        enum {
                ARG_FAIL = 0x100,            /* compatibility only */
                ARG_REVERSE,
                ARG_AFTER,
                ARG_BEFORE,
                ARG_CHECK_INHIBITORS,
                ARG_DRY_RUN,
                ARG_SHOW_TYPES,
                ARG_IRREVERSIBLE,            /* compatibility only */
                ARG_IGNORE_DEPENDENCIES,     /* compatibility only */
                ARG_VALUE,
                ARG_VERSION,
                ARG_USER,
                ARG_SYSTEM,
                ARG_GLOBAL,
                ARG_NO_BLOCK,
                ARG_LEGEND,
                ARG_NO_LEGEND,                /* compatibility only */
                ARG_NO_PAGER,
                ARG_NO_WALL,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_IMAGE_POLICY,
                ARG_NO_RELOAD,
                ARG_KILL_WHOM,
                ARG_KILL_VALUE,
                ARG_NO_ASK_PASSWORD,
                ARG_FAILED,
                ARG_RUNTIME,
                ARG_PLAIN,
                ARG_STATE,
                ARG_JOB_MODE,
                ARG_PRESET_MODE,
                ARG_FIRMWARE_SETUP,
                ARG_BOOT_LOADER_MENU,
                ARG_BOOT_LOADER_ENTRY,
                ARG_NOW,
                ARG_MESSAGE,
                ARG_WITH_DEPENDENCIES,
                ARG_WAIT,
                ARG_WHAT,
                ARG_REBOOT_ARG,
                ARG_TIMESTAMP_STYLE,
                ARG_READ_ONLY,
                ARG_MKDIR,
                ARG_MARKED,
                ARG_NO_WARN,
                ARG_DROP_IN,
                ARG_WHEN,
                ARG_STDIN,
                ARG_KILL_SUBGROUP,
        };

        static const struct option options[] = {
                { "help",                no_argument,       NULL, 'h'                     },
                { "version",             no_argument,       NULL, ARG_VERSION             },
                { "type",                required_argument, NULL, 't'                     },
                { "property",            required_argument, NULL, 'p'                     },
                { "all",                 no_argument,       NULL, 'a'                     },
                { "reverse",             no_argument,       NULL, ARG_REVERSE             },
                { "after",               no_argument,       NULL, ARG_AFTER               },
                { "before",              no_argument,       NULL, ARG_BEFORE              },
                { "show-types",          no_argument,       NULL, ARG_SHOW_TYPES          },
                { "failed",              no_argument,       NULL, ARG_FAILED              },
                { "full",                no_argument,       NULL, 'l'                     },
                { "job-mode",            required_argument, NULL, ARG_JOB_MODE            },
                { "fail",                no_argument,       NULL, ARG_FAIL                }, /* compatibility only */
                { "irreversible",        no_argument,       NULL, ARG_IRREVERSIBLE        }, /* compatibility only */
                { "ignore-dependencies", no_argument,       NULL, ARG_IGNORE_DEPENDENCIES }, /* compatibility only */
                { "ignore-inhibitors",   no_argument,       NULL, 'i'                     }, /* compatibility only */
                { "check-inhibitors",    required_argument, NULL, ARG_CHECK_INHIBITORS    },
                { "value",               no_argument,       NULL, ARG_VALUE               },
                { "user",                no_argument,       NULL, ARG_USER                },
                { "system",              no_argument,       NULL, ARG_SYSTEM              },
                { "global",              no_argument,       NULL, ARG_GLOBAL              },
                { "capsule",             required_argument, NULL, 'C'                     },
                { "wait",                no_argument,       NULL, ARG_WAIT                },
                { "no-block",            no_argument,       NULL, ARG_NO_BLOCK            },
                { "legend",              required_argument, NULL, ARG_LEGEND              },
                { "no-legend",           no_argument,       NULL, ARG_NO_LEGEND           }, /* compatibility only */
                { "no-pager",            no_argument,       NULL, ARG_NO_PAGER            },
                { "no-wall",             no_argument,       NULL, ARG_NO_WALL             },
                { "dry-run",             no_argument,       NULL, ARG_DRY_RUN             },
                { "quiet",               no_argument,       NULL, 'q'                     },
                { "verbose",             no_argument,       NULL, 'v'                     },
                { "no-warn",             no_argument,       NULL, ARG_NO_WARN             },
                { "root",                required_argument, NULL, ARG_ROOT                },
                { "image",               required_argument, NULL, ARG_IMAGE               },
                { "image-policy",        required_argument, NULL, ARG_IMAGE_POLICY        },
                { "force",               no_argument,       NULL, 'f'                     },
                { "no-reload",           no_argument,       NULL, ARG_NO_RELOAD           },
                { "kill-whom",           required_argument, NULL, ARG_KILL_WHOM           },
                { "kill-value",          required_argument, NULL, ARG_KILL_VALUE          },
                { "signal",              required_argument, NULL, 's'                     },
                { "no-ask-password",     no_argument,       NULL, ARG_NO_ASK_PASSWORD     },
                { "host",                required_argument, NULL, 'H'                     },
                { "machine",             required_argument, NULL, 'M'                     },
                { "runtime",             no_argument,       NULL, ARG_RUNTIME             },
                { "lines",               required_argument, NULL, 'n'                     },
                { "output",              required_argument, NULL, 'o'                     },
                { "plain",               no_argument,       NULL, ARG_PLAIN               },
                { "state",               required_argument, NULL, ARG_STATE               },
                { "recursive",           no_argument,       NULL, 'r'                     },
                { "with-dependencies",   no_argument,       NULL, ARG_WITH_DEPENDENCIES   },
                { "preset-mode",         required_argument, NULL, ARG_PRESET_MODE         },
                { "firmware-setup",      no_argument,       NULL, ARG_FIRMWARE_SETUP      },
                { "boot-loader-menu",    required_argument, NULL, ARG_BOOT_LOADER_MENU    },
                { "boot-loader-entry",   required_argument, NULL, ARG_BOOT_LOADER_ENTRY   },
                { "now",                 no_argument,       NULL, ARG_NOW                 },
                { "message",             required_argument, NULL, ARG_MESSAGE             },
                { "show-transaction",    no_argument,       NULL, 'T'                     },
                { "what",                required_argument, NULL, ARG_WHAT                },
                { "reboot-argument",     required_argument, NULL, ARG_REBOOT_ARG          },
                { "timestamp",           required_argument, NULL, ARG_TIMESTAMP_STYLE     },
                { "read-only",           no_argument,       NULL, ARG_READ_ONLY           },
                { "mkdir",               no_argument,       NULL, ARG_MKDIR               },
                { "marked",              no_argument,       NULL, ARG_MARKED              },
                { "drop-in",             required_argument, NULL, ARG_DROP_IN             },
                { "when",                required_argument, NULL, ARG_WHEN                },
                { "stdin",               no_argument,       NULL, ARG_STDIN               },
                { "kill-subgroup",       required_argument, NULL, ARG_KILL_SUBGROUP       },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        /* We default to allowing interactive authorization only in systemctl (not in the legacy commands) */
        arg_ask_password = true;

        while ((c = getopt_long(argc, argv, "hC:t:p:P:alqvfs:H:M:n:o:iTr.::", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return systemctl_help();

                case ARG_VERSION:
                        return version();

                case 't':
                        if (isempty(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--type= requires arguments.");

                        for (const char *p = optarg;;) {
                                _cleanup_free_ char *type = NULL;

                                r = extract_first_word(&p, &type, ",", 0);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse type: %s", optarg);
                                if (r == 0)
                                        break;

                                if (streq(type, "help")) {
                                        help_types();
                                        return 0;
                                }

                                if (unit_type_from_string(type) >= 0) {
                                        if (strv_consume(&arg_types, TAKE_PTR(type)) < 0)
                                                return log_oom();
                                        continue;
                                }

                                /* It's much nicer to use --state= for load states, but let's support this in
                                 * --types= too for compatibility with old versions */
                                if (unit_load_state_from_string(type) >= 0) {
                                        if (strv_consume(&arg_states, TAKE_PTR(type)) < 0)
                                                return log_oom();
                                        continue;
                                }

                                log_error("Unknown unit type or load state '%s'.", type);
                                return log_info_errno(SYNTHETIC_ERRNO(EINVAL),
                                                      "Use -t help to see a list of allowed values.");
                        }

                        break;

                case 'P':
                        SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_ONLY_VALUE, true);
                        _fallthrough_;

                case 'p':
                        /* Make sure that if the empty property list was specified, we won't show any
                           properties. */
                        if (isempty(optarg) && !arg_properties) {
                                arg_properties = new0(char*, 1);
                                if (!arg_properties)
                                        return log_oom();
                        } else
                                for (const char *p = optarg;;) {
                                        _cleanup_free_ char *prop = NULL;

                                        r = extract_first_word(&p, &prop, ",", 0);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to parse property: %s", optarg);
                                        if (r == 0)
                                                break;

                                        if (strv_consume(&arg_properties, TAKE_PTR(prop)) < 0)
                                                return log_oom();
                                }

                        /* If the user asked for a particular property, show it, even if it is empty. */
                        SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_SHOW_EMPTY, true);

                        break;

                case 'a':
                        SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_SHOW_EMPTY, true);
                        arg_all = true;
                        break;

                case ARG_REVERSE:
                        arg_dependency = DEPENDENCY_REVERSE;
                        break;

                case ARG_AFTER:
                        arg_dependency = DEPENDENCY_AFTER;
                        arg_jobs_after = true;
                        break;

                case ARG_BEFORE:
                        arg_dependency = DEPENDENCY_BEFORE;
                        arg_jobs_before = true;
                        break;

                case ARG_SHOW_TYPES:
                        arg_show_types = true;
                        break;

                case ARG_VALUE:
                        SET_FLAG(arg_print_flags, BUS_PRINT_PROPERTY_ONLY_VALUE, true);
                        break;

                case ARG_JOB_MODE:
                        _arg_job_mode = optarg;
                        break;

                case ARG_FAIL:
                        _arg_job_mode = "fail";
                        break;

                case ARG_IRREVERSIBLE:
                        _arg_job_mode = "replace-irreversibly";
                        break;

                case ARG_IGNORE_DEPENDENCIES:
                        _arg_job_mode = "ignore-dependencies";
                        break;

                case ARG_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                case ARG_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                case ARG_GLOBAL:
                        arg_runtime_scope = RUNTIME_SCOPE_GLOBAL;
                        break;

                case 'C':
                        r = capsule_name_is_valid(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Unable to validate capsule name '%s': %m", optarg);
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid capsule name: %s", optarg);

                        arg_host = optarg;
                        arg_transport = BUS_TRANSPORT_CAPSULE;
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                case ARG_WAIT:
                        arg_wait = true;
                        break;

                case ARG_NO_BLOCK:
                        arg_no_block = true;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_LEGEND:
                        r = parse_boolean_argument("--legend", optarg, NULL);
                        if (r < 0)
                                return r;
                        arg_legend = r;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_WALL:
                        arg_no_wall = true;
                        break;

                case ARG_ROOT:
                        r = parse_path_argument(optarg, false, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE:
                        r = parse_path_argument(optarg, false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE_POLICY:
                        r = parse_image_policy_argument(optarg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                case 'l':
                        arg_full = true;
                        break;

                case ARG_FAILED:
                        if (strv_extend(&arg_states, "failed") < 0)
                                return log_oom();

                        break;

                case ARG_DRY_RUN:
                        arg_dry_run = true;
                        break;

                case 'q':
                        arg_quiet = true;

                        if (arg_legend < 0)
                                arg_legend = false;

                        break;

                case 'v':
                        arg_verbose = true;
                        break;

                case 'f':
                        arg_force++;
                        break;

                case ARG_NO_RELOAD:
                        arg_no_reload = true;
                        break;

                case ARG_KILL_WHOM:
                        arg_kill_whom = optarg;
                        break;

                case ARG_KILL_VALUE: {
                        unsigned u;

                        if (isempty(optarg)) {
                                arg_kill_value_set = false;
                                return 0;
                        }

                        /* First, try to parse unsigned, so that we can support the prefixes 0x, 0o, 0b */
                        r = safe_atou_full(optarg, 0, &u);
                        if (r < 0)
                                /* If this didn't work, try as signed integer, without those prefixes */
                                r = safe_atoi(optarg, &arg_kill_value);
                        else if (u > INT_MAX)
                                r = -ERANGE;
                        else
                                arg_kill_value = (int) u;
                        if (r < 0)
                                return log_error_errno(r, "Unable to parse signal queue value: %s", optarg);

                        arg_kill_value_set = true;
                        break;
                }

                case 's':
                        r = parse_signal_argument(optarg, &arg_signal);
                        if (r <= 0)
                                return r;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        r = parse_machine_argument(optarg, &arg_host, &arg_transport);
                        if (r < 0)
                                return r;
                        break;

                case ARG_RUNTIME:
                        arg_runtime = true;
                        break;

                case 'n':
                        if (safe_atou(optarg, &arg_lines) < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse lines '%s'",
                                                       optarg);
                        break;

                case 'o':
                        if (streq(optarg, "help"))
                                return DUMP_STRING_TABLE(output_mode, OutputMode, _OUTPUT_MODE_MAX);

                        arg_output = output_mode_from_string(optarg);
                        if (arg_output < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown output '%s'.",
                                                       optarg);

                        if (OUTPUT_MODE_IS_JSON(arg_output)) {
                                arg_legend = false;
                                arg_plain = true;
                        }
                        break;

                case 'i':
                        arg_check_inhibitors = 0;
                        break;

                case ARG_CHECK_INHIBITORS:
                        r = parse_tristate_argument_with_auto("--check-inhibitors=", optarg, &arg_check_inhibitors);
                        if (r < 0)
                                return r;
                        break;

                case ARG_PLAIN:
                        arg_plain = true;
                        break;

                case ARG_FIRMWARE_SETUP:
                        arg_firmware_setup = true;
                        break;

                case ARG_BOOT_LOADER_MENU:

                        r = parse_sec(optarg, &arg_boot_loader_menu);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --boot-loader-menu= argument '%s': %m", optarg);

                        break;

                case ARG_BOOT_LOADER_ENTRY:

                        if (streq(optarg, "help")) { /* Yes, this means, "help" is not a valid boot loader entry name we can deal with */
                                r = help_boot_loader_entry();
                                if (r < 0)
                                        return r;

                                return 0;
                        }

                        arg_boot_loader_entry = empty_to_null(optarg);
                        break;

                case ARG_STATE:
                        if (isempty(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--state= requires arguments.");

                        for (const char *p = optarg;;) {
                                _cleanup_free_ char *s = NULL;

                                r = extract_first_word(&p, &s, ",", 0);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse state: %s", optarg);
                                if (r == 0)
                                        break;

                                if (streq(s, "help")) {
                                        help_states();
                                        return 0;
                                }

                                if (strv_consume(&arg_states, TAKE_PTR(s)) < 0)
                                        return log_oom();
                        }
                        break;

                case 'r':
                        if (geteuid() != 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EPERM),
                                                       "--recursive requires root privileges.");

                        arg_recursive = true;
                        break;

                case ARG_PRESET_MODE:
                        if (streq(optarg, "help"))
                                return DUMP_STRING_TABLE(unit_file_preset_mode, UnitFilePresetMode, _UNIT_FILE_PRESET_MODE_MAX);

                        arg_preset_mode = unit_file_preset_mode_from_string(optarg);
                        if (arg_preset_mode < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse preset mode: %s.", optarg);

                        break;

                case ARG_NOW:
                        arg_now = true;
                        break;

                case ARG_MESSAGE:
                        if (strv_extend(&arg_wall, optarg) < 0)
                                return log_oom();
                        break;

                case 'T':
                        arg_show_transaction = true;
                        break;

                case ARG_WITH_DEPENDENCIES:
                        arg_with_dependencies = true;
                        break;

                case ARG_WHAT:
                        if (isempty(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--what= requires arguments (see --what=help).");

                        for (const char *p = optarg;;) {
                                _cleanup_free_ char *k = NULL;

                                r = extract_first_word(&p, &k, ",", 0);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse directory type: %s", optarg);
                                if (r == 0)
                                        break;

                                if (streq(k, "help")) {
                                        puts("runtime\n"
                                             "state\n"
                                             "cache\n"
                                             "logs\n"
                                             "configuration\n"
                                             "fdstore\n"
                                             "all");
                                        return 0;
                                }

                                r = strv_consume(&arg_clean_what, TAKE_PTR(k));
                                if (r < 0)
                                        return log_oom();
                        }

                        break;

                case ARG_REBOOT_ARG:
                        arg_reboot_argument = optarg;
                        break;

                case ARG_TIMESTAMP_STYLE:
                        if (streq(optarg, "help"))
                                return DUMP_STRING_TABLE(timestamp_style, TimestampStyle, _TIMESTAMP_STYLE_MAX);

                        arg_timestamp_style = timestamp_style_from_string(optarg);
                        if (arg_timestamp_style < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid value: %s.", optarg);

                        break;

                case ARG_READ_ONLY:
                        arg_read_only = true;
                        break;

                case ARG_MKDIR:
                        arg_mkdir = true;
                        break;

                case ARG_MARKED:
                        arg_marked = true;
                        break;

                case ARG_NO_WARN:
                        arg_no_warn = true;
                        break;

                case ARG_DROP_IN:
                        arg_drop_in = optarg;
                        break;

                case ARG_WHEN:
                        if (streq(optarg, "show")) {
                                arg_action = ACTION_SYSTEMCTL_SHOW_SHUTDOWN;
                                return 1;
                        }

                        if (STR_IN_SET(optarg, "", "cancel")) {
                                arg_action = ACTION_CANCEL_SHUTDOWN;
                                return 1;
                        }

                        if (streq(optarg, "auto")) {
                                arg_when = USEC_INFINITY; /* logind chooses on server side */
                                break;
                        }

                        r = parse_timestamp(optarg, &arg_when);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --when= argument '%s': %m", optarg);

                        if (!timestamp_is_set(arg_when))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Invalid timestamp '%s' specified for --when=.", optarg);

                        break;

                case ARG_STDIN:
                        arg_stdin = true;
                        break;

                case ARG_KILL_SUBGROUP: {
                        if (empty_or_root(optarg)) {
                                arg_kill_subgroup = mfree(arg_kill_subgroup);
                                break;
                        }

                        _cleanup_free_ char *p = NULL;
                        if (path_simplify_alloc(optarg, &p) < 0)
                                return log_oom();

                        if (!path_is_safe(p))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Control group sub-path '%s' is not valid.", p);

                        free_and_replace(arg_kill_subgroup, p);
                        break;
                }

                case '.':
                        /* Output an error mimicking getopt, and print a hint afterwards */
                        log_error("%s: invalid option -- '.'", program_invocation_name);
                        log_notice("Hint: to specify units starting with a dash, use \"--\":\n"
                                   "      %s [OPTIONS...] COMMAND -- -.%s ...",
                                   program_invocation_name, optarg ?: "mount");
                        _fallthrough_;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        /* If we are in --user mode, there's no point in talking to PolicyKit or the infra to query system
         * passwords */
        if (arg_runtime_scope != RUNTIME_SCOPE_SYSTEM)
                arg_ask_password = false;

        if (arg_transport == BUS_TRANSPORT_REMOTE && arg_runtime_scope != RUNTIME_SCOPE_SYSTEM)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Cannot access user instance remotely.");

        if (arg_transport == BUS_TRANSPORT_CAPSULE && arg_runtime_scope != RUNTIME_SCOPE_USER)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Cannot access system instance with --capsule=/-C.");

        if (arg_wait && arg_no_block)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--wait may not be combined with --no-block.");

        if (arg_marked) {
                if (!STRPTR_IN_SET(argv[optind], "reload-or-restart", "start", "stop"))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--marked may only be used with 'reload-or-restart', 'start', or 'stop'.");
                if (optind + 1 < argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "No additional arguments allowed with '%s --marked'.", strna(argv[optind]));
                if (arg_wait)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--marked --wait is not supported.");
                if (arg_show_transaction)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--marked --show-transaction is not supported.");

        } else if (STRPTR_IN_SET(argv[optind], "reload-or-restart", "start", "stop")) {
                if (optind + 1 >= argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "List of units to %s is required.", strna(argv[optind]));
        }

        if (arg_image && arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Please specify either --root= or --image=, the combination of both is not supported.");

        return 1;
}

int systemctl_dispatch_parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        if (invoked_as(argv, "halt")) {
                arg_action = ACTION_HALT;
                return halt_parse_argv(argc, argv);

        } else if (invoked_as(argv, "poweroff")) {
                arg_action = ACTION_POWEROFF;
                return halt_parse_argv(argc, argv);

        } else if (invoked_as(argv, "reboot")) {
                arg_action = ACTION_REBOOT;
                return halt_parse_argv(argc, argv);

        } else if (invoked_as(argv, "shutdown")) {
                arg_action = ACTION_POWEROFF;
                return shutdown_parse_argv(argc, argv);
        }

        arg_action = ACTION_SYSTEMCTL;
        return systemctl_parse_argv(argc, argv);
}
