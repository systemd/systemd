/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <locale.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "build.h"
#include "bus-util.h"
#include "dissect-image.h"
#include "install.h"
#include "main-func.h"
#include "mount-util.h"
#include "output-mode.h"
#include "pager.h"
#include "parse-argument.h"
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "reboot-util.h"
#include "rlimit-util.h"
#include "sigbus.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "systemctl-add-dependency.h"
#include "systemctl-cancel-job.h"
#include "systemctl-clean-or-freeze.h"
#include "systemctl-compat-halt.h"
#include "systemctl-compat-runlevel.h"
#include "systemctl-compat-shutdown.h"
#include "systemctl-compat-telinit.h"
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
#include "systemctl-sysv-compat.h"
#include "systemctl-trivial-method.h"
#include "systemctl-util.h"
#include "systemctl-whoami.h"
#include "systemctl.h"
#include "terminal-util.h"
#include "time-util.h"
#include "verbs.h"
#include "virt.h"

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
               "     --kill-whom=WHOM    Whom to send signal to\n"
               "     --kill-value=INT    Signal value to enqueue\n"
               "  -s --signal=SIGNAL     Which signal to send\n"
               "     --what=RESOURCES    Which types of resources to remove\n"
               "     --now               Start or stop unit after enabling or disabling it\n"
               "     --dry-run           Only print what would be done\n"
               "                         Currently supported by verbs: halt, poweroff, reboot,\n"
               "                             kexec, soft-reboot, suspend, hibernate, \n"
               "                             suspend-then-hibernate, hybrid-sleep, default,\n"
               "                             rescue, emergency, and exit.\n"
               "  -q --quiet             Suppress output\n"
               "     --no-warn           Suppress several warnings shown by default\n"
               "     --wait              For (re)start, wait until service stopped again\n"
               "                         For is-system-running, wait until startup is completed\n"
               "     --no-block          Do not wait until operation finished\n"
               "     --no-wall           Don't send wall message before halt/power-off/reboot\n"
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
               "     --plain             Print unit dependencies as a list instead of a tree\n"
               "     --timestamp=FORMAT  Change format of printed timestamps (pretty, unix,\n"
               "                             us, utc, us+utc)\n"
               "     --read-only         Create read-only bind mount\n"
               "     --mkdir             Create directory before mounting, if missing\n"
               "     --marked            Restart/reload previously marked units\n"
               "     --drop-in=NAME      Edit unit files using the specified drop-in file name\n"
               "     --when=TIME         Schedule halt/power-off/reboot/kexec action after\n"
               "                         a certain timestamp\n"
               "     --stdin             Read contents of edited file from stdin\n"
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
                { "wait",                no_argument,       NULL, ARG_WAIT                },
                { "no-block",            no_argument,       NULL, ARG_NO_BLOCK            },
                { "legend",              required_argument, NULL, ARG_LEGEND              },
                { "no-legend",           no_argument,       NULL, ARG_NO_LEGEND           }, /* compatibility only */
                { "no-pager",            no_argument,       NULL, ARG_NO_PAGER            },
                { "no-wall",             no_argument,       NULL, ARG_NO_WALL             },
                { "dry-run",             no_argument,       NULL, ARG_DRY_RUN             },
                { "quiet",               no_argument,       NULL, 'q'                     },
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
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        /* We default to allowing interactive authorization only in systemctl (not in the legacy commands) */
        arg_ask_password = true;

        while ((c = getopt_long(argc, argv, "ht:p:P:alqfs:H:M:n:o:iTr.::", options, NULL)) >= 0)

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
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
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
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(output_mode, OutputMode, _OUTPUT_MODE_MAX);
                                return 0;
                        }

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
                        r = parse_tristate_full(optarg, "auto", &arg_check_inhibitors);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --check-inhibitors= argument: %s", optarg);
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
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(unit_file_preset_mode, UnitFilePresetMode, _UNIT_FILE_PRESET_MODE_MAX);
                                return 0;
                        }

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
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--what= requires arguments.");

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
                                             "fdstore");
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
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(timestamp_style, TimestampStyle, _TIMESTAMP_STYLE_MAX);
                                return 0;
                        }

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
                                r = logind_show_shutdown();
                                if (r < 0 && r != -ENODATA)
                                        return r;

                                return 0;
                        }

                        if (STR_IN_SET(optarg, "", "cancel")) {
                                arg_when = USEC_INFINITY;
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

        if (arg_wait && arg_no_block)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--wait may not be combined with --no-block.");

        bool do_reload_or_restart = streq_ptr(argv[optind], "reload-or-restart");
        if (arg_marked) {
                if (!do_reload_or_restart)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--marked may only be used with 'reload-or-restart'.");
                if (optind + 1 < argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "No additional arguments allowed with 'reload-or-restart --marked'.");
                if (arg_wait)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--marked --wait is not supported.");
                if (arg_show_transaction)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "--marked --show-transaction is not supported.");

        } else if (do_reload_or_restart) {
                if (optind + 1 >= argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "List of units to restart/reload is required.");
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

        } else if (invoked_as(argv, "init")) {

                /* Matches invocations as "init" as well as "telinit", which are synonymous when run
                 * as PID != 1 on SysV.
                 *
                 * On SysV "telinit" was the official command to communicate with PID 1, but "init" would
                 * redirect itself to "telinit" if called with PID != 1. We follow the same logic here still,
                 * though we add one level of indirection, as we implement "telinit" in "systemctl". Hence,
                 * for us if you invoke "init" you get "systemd", but it will execve() "systemctl"
                 * immediately with argv[] unmodified if PID is != 1. If you invoke "telinit" you directly
                 * get "systemctl". In both cases we shall do the same thing, which is why we do
                 * invoked_as(argv, "init") here, as a quick way to match both.
                 *
                 * Also see redirect_telinit() in src/core/main.c. */

                if (sd_booted() > 0) {
                        arg_action = _ACTION_INVALID;
                        return telinit_parse_argv(argc, argv);
                } else {
                        /* Hmm, so some other init system is running, we need to forward this request to it.
                         */
                        arg_action = ACTION_TELINIT;
                        return 1;
                }

        } else if (invoked_as(argv, "runlevel")) {
                arg_action = ACTION_RUNLEVEL;
                return runlevel_parse_argv(argc, argv);
        }

        arg_action = ACTION_SYSTEMCTL;
        return systemctl_parse_argv(argc, argv);
}

#ifndef FUZZ_SYSTEMCTL_PARSE_ARGV
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
                { "start",                 2,        VERB_ANY, VERB_ONLINE_ONLY, verb_start                   },
                { "stop",                  2,        VERB_ANY, VERB_ONLINE_ONLY, verb_start                   },
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

        /* The journal merging logic potentially needs a lot of fds. */
        (void) rlimit_nofile_bump(HIGH_RLIMIT_NOFILE);

        sigbus_install();

        r = systemctl_dispatch_parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (proc_mounted() == 0)
                log_full(arg_no_warn ? LOG_DEBUG : LOG_WARNING,
                         "%s%s/proc/ is not mounted. This is not a supported mode of operation. Please fix\n"
                         "your invocation environment to mount /proc/ and /sys/ properly. Proceeding anyway.\n"
                         "Your mileage may vary.",
                         emoji_enabled() ? special_glyph(SPECIAL_GLYPH_WARNING_SIGN) : "",
                         emoji_enabled() ? " " : "");

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
                                DISSECT_IMAGE_VALIDATE_OS,
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

        case ACTION_RUNLEVEL2:
        case ACTION_RUNLEVEL3:
        case ACTION_RUNLEVEL4:
        case ACTION_RUNLEVEL5:
        case ACTION_RESCUE:
                r = start_with_fallback();
                break;

        case ACTION_RELOAD:
        case ACTION_REEXEC:
                r = reload_with_fallback();
                break;

        case ACTION_CANCEL_SHUTDOWN:
                r = logind_cancel_shutdown();
                break;

        case ACTION_SHOW_SHUTDOWN:
                r = logind_show_shutdown();
                break;

        case ACTION_RUNLEVEL:
                r = runlevel_main();
                break;

        case ACTION_TELINIT:
                r = exec_telinit(argv);
                break;

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
#endif
