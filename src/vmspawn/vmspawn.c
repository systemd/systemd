/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-id128.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "architecture.h"
#include "bootspec.h"
#include "build.h"
#include "bus-error.h"
#include "bus-internal.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "capability-util.h"
#include "common-signal.h"
#include "copy.h"
#include "discover-image.h"
#include "dissect-image.h"
#include "escape.h"
#include "ether-addr-util.h"
#include "event-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fork-notify.h"
#include "format-util.h"
#include "fs-util.h"
#include "gpt.h"
#include "group-record.h"
#include "hexdecoct.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "log.h"
#include "machine-bind-user.h"
#include "machine-credential.h"
#include "main-func.h"
#include "mkdir.h"
#include "namespace-util.h"
#include "netif-util.h"
#include "nsresource.h"
#include "osc-context.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "pidref.h"
#include "polkit-agent.h"
#include "pretty-print.h"
#include "process-util.h"
#include "ptyfwd.h"
#include "random-util.h"
#include "rm-rf.h"
#include "signal-util.h"
#include "snapshot-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "sync-util.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "unit-name.h"
#include "user-record.h"
#include "user-util.h"
#include "utf8.h"
#include "vmspawn-mount.h"
#include "vmspawn-register.h"
#include "vmspawn-scope.h"
#include "vmspawn-settings.h"
#include "vmspawn-util.h"

#define VM_TAP_HASH_KEY SD_ID128_MAKE(01,d0,c6,4c,2b,df,24,fb,c0,f8,b2,09,7d,59,b2,93)

typedef enum TpmStateMode {
        TPM_STATE_OFF,      /* keep no state around */
        TPM_STATE_AUTO,     /* keep state around if not ephemeral, derive path from image/directory */
        TPM_STATE_PATH,     /* explicitly specified location */
        _TPM_STATE_MODE_MAX,
        _TPM_STATE_MODE_INVALID = -EINVAL,
} TpmStateMode;

typedef struct SSHInfo {
        unsigned cid;
        char *private_key_path;
        unsigned port;
} SSHInfo;

typedef struct ShutdownInfo {
        SSHInfo *ssh_info;
        PidRef *pidref;
} ShutdownInfo;

static bool arg_quiet = false;
static PagerFlags arg_pager_flags = 0;
static char *arg_directory = NULL;
static char *arg_image = NULL;
static ImageFormat arg_image_format = IMAGE_FORMAT_RAW;
static char *arg_machine = NULL;
static char *arg_slice = NULL;
static char **arg_property = NULL;
static char *arg_cpus = NULL;
static uint64_t arg_ram = UINT64_C(2) * U64_GB;
static int arg_kvm = -1;
static int arg_vsock = -1;
static unsigned arg_vsock_cid = VMADDR_CID_ANY;
static int arg_tpm = -1;
static char *arg_linux = NULL;
static char **arg_initrds = NULL;
static ConsoleMode arg_console_mode = CONSOLE_INTERACTIVE;
static NetworkStack arg_network_stack = NETWORK_STACK_NONE;
static int arg_secure_boot = -1;
static MachineCredentialContext arg_credentials = {};
static uid_t arg_uid_shift = UID_INVALID, arg_uid_range = 0x10000U;
static RuntimeMountContext arg_runtime_mounts = {};
static char *arg_firmware = NULL;
static char *arg_forward_journal = NULL;
static bool arg_register = true;
static bool arg_keep_unit = false;
static sd_id128_t arg_uuid = {};
static char **arg_kernel_cmdline_extra = NULL;
static ExtraDriveContext arg_extra_drives = {};
static char *arg_background = NULL;
static bool arg_pass_ssh_key = true;
static char *arg_ssh_key_type = NULL;
static bool arg_discard_disk = true;
struct ether_addr arg_network_provided_mac = {};
static char **arg_smbios11 = NULL;
static uint64_t arg_grow_image = 0;
static char *arg_tpm_state_path = NULL;
static TpmStateMode arg_tpm_state_mode = TPM_STATE_AUTO;
static bool arg_ask_password = true;
static bool arg_notify_ready = true;
static char **arg_bind_user = NULL;
static char *arg_bind_user_shell = NULL;
static bool arg_bind_user_shell_copy = false;
static char **arg_bind_user_groups = NULL;
static bool arg_ephemeral = false;
static RuntimeScope arg_runtime_scope = _RUNTIME_SCOPE_INVALID;

STATIC_DESTRUCTOR_REGISTER(arg_directory, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_machine, freep);
STATIC_DESTRUCTOR_REGISTER(arg_slice, freep);
STATIC_DESTRUCTOR_REGISTER(arg_cpus, freep);
STATIC_DESTRUCTOR_REGISTER(arg_credentials, machine_credential_context_done);
STATIC_DESTRUCTOR_REGISTER(arg_firmware, freep);
STATIC_DESTRUCTOR_REGISTER(arg_linux, freep);
STATIC_DESTRUCTOR_REGISTER(arg_initrds, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_runtime_mounts, runtime_mount_context_done);
STATIC_DESTRUCTOR_REGISTER(arg_forward_journal, freep);
STATIC_DESTRUCTOR_REGISTER(arg_kernel_cmdline_extra, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_extra_drives, extra_drive_context_done);
STATIC_DESTRUCTOR_REGISTER(arg_background, freep);
STATIC_DESTRUCTOR_REGISTER(arg_ssh_key_type, freep);
STATIC_DESTRUCTOR_REGISTER(arg_smbios11, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm_state_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_property, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_bind_user, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_bind_user_shell, freep);
STATIC_DESTRUCTOR_REGISTER(arg_bind_user_groups, strv_freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("systemd-vmspawn", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] [ARGUMENTS...]\n\n"
               "%5$sSpawn a command or OS in a virtual machine.%6$s\n\n"
               "  -h --help                Show this help\n"
               "     --version             Print version string\n"
               "  -q --quiet               Do not show status information\n"
               "     --no-pager            Do not pipe output into a pager\n"
               "     --no-ask-password     Do not prompt for password\n"
               "     --user                Interact with user manager\n"
               "     --system              Interact with system manager\n"
               "\n%3$sImage:%4$s\n"
               "  -D --directory=PATH      Root directory for the VM\n"
               "  -x --ephemeral           Run VM with snapshot of the disk or directory\n"
               "  -i --image=FILE|DEVICE   Root file system disk image or device for the VM\n"
               "     --image-format=FORMAT Specify disk image format (raw, qcow2; default: raw)\n"
               "\n%3$sHost Configuration:%4$s\n"
               "     --cpus=CPUS           Configure number of CPUs in guest\n"
               "     --ram=BYTES           Configure guest's RAM size\n"
               "     --kvm=BOOL            Enable use of KVM\n"
               "     --vsock=BOOL          Override autodetection of VSOCK support\n"
               "     --vsock-cid=CID       Specify the CID to use for the guest's VSOCK support\n"
               "     --tpm=BOOL            Enable use of a virtual TPM\n"
               "     --tpm-state=off|auto|PATH\n"
               "                           Where to store TPM state\n"
               "     --linux=PATH          Specify the linux kernel for direct kernel boot\n"
               "     --initrd=PATH         Specify the initrd for direct kernel boot\n"
               "  -n --network-tap         Create a TAP device for networking\n"
               "     --network-user-mode   Use user mode networking\n"
               "     --secure-boot=BOOL    Enable searching for firmware supporting SecureBoot\n"
               "     --firmware=PATH|list  Select firmware definition file (or list available)\n"
               "     --discard-disk=BOOL   Control processing of discard requests\n"
               "  -G --grow-image=BYTES    Grow image file to specified size in bytes\n"
               "\n%3$sExecution:%4$s\n"
               "  -s --smbios11=STRING     Pass an arbitrary SMBIOS Type #11 string to the VM\n"
               "     --notify-ready=BOOL   Wait for ready notification from the VM\n"
               "\n%3$sSystem Identity:%4$s\n"
               "  -M --machine=NAME        Set the machine name for the VM\n"
               "     --uuid=UUID           Set a specific machine UUID for the VM\n"
               "\n%3$sProperties:%4$s\n"
               "  -S --slice=SLICE         Place the VM in the specified slice\n"
               "     --property=NAME=VALUE Set scope unit property\n"
               "     --register=BOOLEAN    Register VM as machine\n"
               "     --keep-unit           Do not register a scope for the machine, reuse\n"
               "                           the service unit vmspawn is running in\n"
               "\n%3$sUser Namespacing:%4$s\n"
               "     --private-users=UIDBASE[:NUIDS]\n"
               "                           Configure the UID/GID range to map into the\n"
               "                           virtiofsd namespace\n"
               "\n%3$sMounts:%4$s\n"
               "     --bind=SOURCE[:TARGET]\n"
               "                           Mount a file or directory from the host into the VM\n"
               "     --bind-ro=SOURCE[:TARGET]\n"
               "                           Mount a file or directory, but read-only\n"
               "     --extra-drive=PATH[:FORMAT]\n"
               "                           Adds an additional disk to the virtual machine\n"
               "                           (format: raw, qcow2; default: raw)\n"
               "     --bind-user=NAME       Bind user from host to virtual machine\n"
               "     --bind-user-shell=BOOL|PATH\n"
               "                            Configure the shell to use for --bind-user= users\n"
               "     --bind-user-group=GROUP\n"
               "                            Add an auxiliary group to --bind-user= users\n"
               "\n%3$sIntegration:%4$s\n"
               "     --forward-journal=FILE|DIR\n"
               "                           Forward the VM's journal to the host\n"
               "     --pass-ssh-key=BOOL   Create an SSH key to access the VM\n"
               "     --ssh-key-type=TYPE   Choose what type of SSH key to pass\n"
               "\n%3$sInput/Output:%4$s\n"
               "     --console=MODE        Console mode (interactive, native, gui)\n"
               "     --background=COLOR    Set ANSI color for background\n"
               "\n%3$sCredentials:%4$s\n"
               "     --set-credential=ID:VALUE\n"
               "                           Pass a credential with literal value to the VM\n"
               "     --load-credential=ID:PATH\n"
               "                           Load credential for the VM from file or AF_UNIX\n"
               "                           stream socket.\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_environment(void) {
        const char *e;
        int r;

        e = getenv("SYSTEMD_VMSPAWN_NETWORK_MAC");
        if (e) {
                r = parse_ether_addr(e, &arg_network_provided_mac);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse provided MAC address via environment variable");
        }

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_CPUS,
                ARG_RAM,
                ARG_KVM,
                ARG_VSOCK,
                ARG_VSOCK_CID,
                ARG_TPM,
                ARG_LINUX,
                ARG_INITRD,
                ARG_QEMU_GUI,
                ARG_NETWORK_USER_MODE,
                ARG_UUID,
                ARG_REGISTER,
                ARG_KEEP_UNIT,
                ARG_BIND,
                ARG_BIND_RO,
                ARG_EXTRA_DRIVE,
                ARG_SECURE_BOOT,
                ARG_PRIVATE_USERS,
                ARG_FORWARD_JOURNAL,
                ARG_PASS_SSH_KEY,
                ARG_SSH_KEY_TYPE,
                ARG_SET_CREDENTIAL,
                ARG_LOAD_CREDENTIAL,
                ARG_FIRMWARE,
                ARG_DISCARD_DISK,
                ARG_CONSOLE,
                ARG_BACKGROUND,
                ARG_TPM_STATE,
                ARG_NO_ASK_PASSWORD,
                ARG_PROPERTY,
                ARG_NOTIFY_READY,
                ARG_BIND_USER,
                ARG_BIND_USER_SHELL,
                ARG_BIND_USER_GROUP,
                ARG_SYSTEM,
                ARG_USER,
                ARG_IMAGE_FORMAT,
        };

        static const struct option options[] = {
                { "help",              no_argument,       NULL, 'h'                   },
                { "version",           no_argument,       NULL, ARG_VERSION           },
                { "quiet",             no_argument,       NULL, 'q'                   },
                { "no-pager",          no_argument,       NULL, ARG_NO_PAGER          },
                { "image",             required_argument, NULL, 'i'                   },
                { "image-format",      required_argument, NULL, ARG_IMAGE_FORMAT      },
                { "ephemeral",         no_argument,       NULL, 'x'                   },
                { "directory",         required_argument, NULL, 'D'                   },
                { "machine",           required_argument, NULL, 'M'                   },
                { "slice",             required_argument, NULL, 'S'                   },
                { "cpus",              required_argument, NULL, ARG_CPUS              },
                { "qemu-smp",          required_argument, NULL, ARG_CPUS              }, /* Compat alias */
                { "ram",               required_argument, NULL, ARG_RAM               },
                { "qemu-mem",          required_argument, NULL, ARG_RAM               }, /* Compat alias */
                { "kvm",               required_argument, NULL, ARG_KVM               },
                { "qemu-kvm",          required_argument, NULL, ARG_KVM               }, /* Compat alias */
                { "vsock",             required_argument, NULL, ARG_VSOCK             },
                { "qemu-vsock",        required_argument, NULL, ARG_VSOCK             }, /* Compat alias */
                { "vsock-cid",         required_argument, NULL, ARG_VSOCK_CID         },
                { "tpm",               required_argument, NULL, ARG_TPM               },
                { "linux",             required_argument, NULL, ARG_LINUX             },
                { "initrd",            required_argument, NULL, ARG_INITRD            },
                { "console",           required_argument, NULL, ARG_CONSOLE           },
                { "qemu-gui",          no_argument,       NULL, ARG_QEMU_GUI          }, /* compat option */
                { "network-tap",       no_argument,       NULL, 'n'                   },
                { "network-user-mode", no_argument,       NULL, ARG_NETWORK_USER_MODE },
                { "uuid",              required_argument, NULL, ARG_UUID              },
                { "register",          required_argument, NULL, ARG_REGISTER          },
                { "keep-unit",         no_argument,       NULL, ARG_KEEP_UNIT         },
                { "bind",              required_argument, NULL, ARG_BIND              },
                { "bind-ro",           required_argument, NULL, ARG_BIND_RO           },
                { "extra-drive",       required_argument, NULL, ARG_EXTRA_DRIVE       },
                { "secure-boot",       required_argument, NULL, ARG_SECURE_BOOT       },
                { "private-users",     required_argument, NULL, ARG_PRIVATE_USERS     },
                { "forward-journal",   required_argument, NULL, ARG_FORWARD_JOURNAL   },
                { "pass-ssh-key",      required_argument, NULL, ARG_PASS_SSH_KEY      },
                { "ssh-key-type",      required_argument, NULL, ARG_SSH_KEY_TYPE      },
                { "set-credential",    required_argument, NULL, ARG_SET_CREDENTIAL    },
                { "load-credential",   required_argument, NULL, ARG_LOAD_CREDENTIAL   },
                { "firmware",          required_argument, NULL, ARG_FIRMWARE          },
                { "discard-disk",      required_argument, NULL, ARG_DISCARD_DISK      },
                { "background",        required_argument, NULL, ARG_BACKGROUND        },
                { "smbios11",          required_argument, NULL, 's'                   },
                { "grow-image",        required_argument, NULL, 'G'                   },
                { "tpm-state",         required_argument, NULL, ARG_TPM_STATE         },
                { "no-ask-password",   no_argument,       NULL, ARG_NO_ASK_PASSWORD   },
                { "property",          required_argument, NULL, ARG_PROPERTY          },
                { "notify-ready",      required_argument, NULL, ARG_NOTIFY_READY      },
                { "bind-user",         required_argument, NULL, ARG_BIND_USER         },
                { "bind-user-shell",   required_argument, NULL, ARG_BIND_USER_SHELL   },
                { "bind-user-group",   required_argument, NULL, ARG_BIND_USER_GROUP   },
                { "system",            no_argument,       NULL, ARG_SYSTEM            },
                { "user",              no_argument,       NULL, ARG_USER              },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        optind = 0;
        while ((c = getopt_long(argc, argv, "+hD:i:xM:nqs:G:S:", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'q':
                        arg_quiet = true;
                        break;

                case 'D':
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_directory);
                        if (r < 0)
                                return r;

                        break;

                case 'i':
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;

                        break;

                case ARG_IMAGE_FORMAT:
                        arg_image_format = image_format_from_string(optarg);
                        if (arg_image_format < 0)
                                return log_error_errno(arg_image_format,
                                                       "Invalid image format: %s", optarg);
                        break;

                case 'M':
                        if (isempty(optarg))
                                arg_machine = mfree(arg_machine);
                        else {
                                if (!hostname_is_valid(optarg, 0))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Invalid machine name: %s", optarg);

                                r = free_and_strdup(&arg_machine, optarg);
                                if (r < 0)
                                        return log_oom();
                        }
                        break;

                case 'x':
                        arg_ephemeral = true;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_CPUS:
                        r = free_and_strdup_warn(&arg_cpus, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_RAM:
                        r = parse_size(optarg, 1024, &arg_ram);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --ram=%s: %m", optarg);
                        break;

                case ARG_KVM:
                        r = parse_tristate_argument_with_auto("--kvm=", optarg, &arg_kvm);
                        if (r < 0)
                                return r;
                        break;

                case ARG_VSOCK:
                        r = parse_tristate_argument_with_auto("--vsock=", optarg, &arg_vsock);
                        if (r < 0)
                                return r;
                        break;

                case ARG_VSOCK_CID:
                        if (isempty(optarg))
                                arg_vsock_cid = VMADDR_CID_ANY;
                        else {
                                unsigned cid;

                                r = vsock_parse_cid(optarg, &cid);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse --vsock-cid: %s", optarg);
                                if (!VSOCK_CID_IS_REGULAR(cid))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified CID is not regular, refusing: %u", cid);

                                arg_vsock_cid = cid;
                        }
                        break;

                case ARG_TPM:
                        r = parse_tristate_argument_with_auto("--tpm=", optarg, &arg_tpm);
                        if (r < 0)
                                return r;
                        break;

                case ARG_LINUX:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_linux);
                        if (r < 0)
                                return r;
                        break;

                case ARG_INITRD: {
                        _cleanup_free_ char *initrd_path = NULL;
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &initrd_path);
                        if (r < 0)
                                return r;

                        r = strv_consume(&arg_initrds, TAKE_PTR(initrd_path));
                        if (r < 0)
                                return log_oom();

                        break;
                }

                case ARG_CONSOLE:
                        arg_console_mode = console_mode_from_string(optarg);
                        if (arg_console_mode < 0)
                                return log_error_errno(arg_console_mode, "Failed to parse specified console mode: %s", optarg);

                        break;

                case ARG_QEMU_GUI:
                        arg_console_mode = CONSOLE_GUI;
                        break;

                case 'n':
                        arg_network_stack = NETWORK_STACK_TAP;
                        break;

                case ARG_NETWORK_USER_MODE:
                        arg_network_stack = NETWORK_STACK_USER;
                        break;

                case ARG_UUID:
                        r = id128_from_string_nonzero(optarg, &arg_uuid);
                        if (r == -ENXIO)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Machine UUID may not be all zeroes.");
                        if (r < 0)
                                return log_error_errno(r, "Invalid UUID: %s", optarg);

                        break;

                case ARG_REGISTER:
                        r = parse_boolean_argument("--register=", optarg, &arg_register);
                        if (r < 0)
                                return r;

                        break;

                case ARG_KEEP_UNIT:
                        arg_keep_unit = true;
                        break;

                case ARG_BIND:
                case ARG_BIND_RO:
                        r = runtime_mount_parse(&arg_runtime_mounts, optarg, c == ARG_BIND_RO);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --bind(-ro)= argument %s: %m", optarg);

                        break;

                case ARG_EXTRA_DRIVE: {
                        _cleanup_free_ char *buf = NULL, *drive_path = NULL;
                        ImageFormat format = IMAGE_FORMAT_RAW;

                        const char *colon = strrchr(optarg, ':');
                        if (colon) {
                                ImageFormat f = image_format_from_string(colon + 1);
                                if (f < 0)
                                        log_debug_errno(f, "Failed to parse image format '%s', assuming it is a part of path, ignoring: %m", colon + 1);
                                else {
                                        format = f;
                                        buf = strndup(optarg, colon - optarg);
                                        if (!buf)
                                                return log_oom();
                                }
                        }

                        r = parse_path_argument(buf ?: optarg, /* suppress_root= */ false, &drive_path);
                        if (r < 0)
                                return r;

                        if (!GREEDY_REALLOC(arg_extra_drives.drives, arg_extra_drives.n_drives + 1))
                                return log_oom();

                        arg_extra_drives.drives[arg_extra_drives.n_drives++] = (ExtraDrive) {
                                .path = TAKE_PTR(drive_path),
                                .format = format,
                        };

                        break;
                }

                case ARG_SECURE_BOOT:
                        r = parse_tristate_argument_with_auto("--secure-boot=", optarg, &arg_secure_boot);
                        if (r < 0)
                                return r;
                        break;

                case ARG_PRIVATE_USERS:
                        r = parse_userns_uid_range(optarg, &arg_uid_shift, &arg_uid_range);
                        if (r < 0)
                                return r;
                        break;

                case ARG_FORWARD_JOURNAL:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_forward_journal);
                        if (r < 0)
                                return r;
                        break;

                case ARG_PASS_SSH_KEY:
                        r = parse_boolean_argument("--pass-ssh-key=", optarg, &arg_pass_ssh_key);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SSH_KEY_TYPE:
                        if (!string_is_safe(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid value for --arg-ssh-key-type=: %s", optarg);

                        r = free_and_strdup_warn(&arg_ssh_key_type, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SET_CREDENTIAL: {
                        r = machine_credential_set(&arg_credentials, optarg);
                        if (r < 0)
                                return r;
                        break;
                }

                case ARG_LOAD_CREDENTIAL: {
                        r = machine_credential_load(&arg_credentials, optarg);
                        if (r < 0)
                                return r;

                        break;
                }

                case ARG_FIRMWARE:
                        if (streq(optarg, "list")) {
                                _cleanup_strv_free_ char **l = NULL;

                                r = list_ovmf_config(&l);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to list firmwares: %m");

                                bool nl = false;
                                fputstrv(stdout, l, "\n", &nl);
                                if (nl)
                                        putchar('\n');

                                return 0;
                        }

                        if (!isempty(optarg) && !path_is_absolute(optarg) && !startswith(optarg, "./"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Absolute path or path starting with './' required.");

                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_firmware);
                        if (r < 0)
                                return r;

                        break;

                case ARG_DISCARD_DISK:
                        r = parse_boolean_argument("--discard-disk=", optarg, &arg_discard_disk);
                        if (r < 0)
                                return r;
                        break;

                case ARG_BACKGROUND:
                        r = parse_background_argument(optarg, &arg_background);
                        if (r < 0)
                                return r;
                        break;

                case 's':
                        if (isempty(optarg)) {
                                arg_smbios11 = strv_free(arg_smbios11);
                                break;
                        }

                        if (!utf8_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "SMBIOS Type 11 string is not UTF-8 clean, refusing: %s", optarg);

                        if (strv_extend(&arg_smbios11, optarg) < 0)
                                return log_oom();

                        break;

                case 'G':
                        if (isempty(optarg)) {
                                arg_grow_image = 0;
                                break;
                        }

                        r = parse_size(optarg, 1024, &arg_grow_image);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --grow-image= parameter: %s", optarg);

                        break;

                case ARG_TPM_STATE:
                        if (path_is_valid(optarg) && (path_is_absolute(optarg) || path_startswith(optarg, "./"))) {
                                r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_tpm_state_path);
                                if (r < 0)
                                        return r;

                                arg_tpm_state_mode = TPM_STATE_PATH;
                                break;
                        }

                        r = isempty(optarg) ? false :
                                streq(optarg, "auto") ? true :
                                parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --tpm-state= parameter: %s", optarg);

                        arg_tpm_state_mode = r ? TPM_STATE_AUTO : TPM_STATE_OFF;
                        arg_tpm_state_path = mfree(arg_tpm_state_path);
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case 'S': {
                        _cleanup_free_ char *mangled = NULL;

                        r = unit_name_mangle_with_suffix(optarg, /* operation= */ NULL, UNIT_NAME_MANGLE_WARN, ".slice", &mangled);
                        if (r < 0)
                                return log_error_errno(r, "Failed to turn '%s' into unit name: %m", optarg);

                        free_and_replace(arg_slice, mangled);
                        break;
                }

                case ARG_PROPERTY:
                        if (strv_extend(&arg_property, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_NOTIFY_READY:
                        r = parse_boolean_argument("--notify-ready=", optarg, &arg_notify_ready);
                        if (r < 0)
                                return r;

                        break;

                case ARG_BIND_USER:
                        if (!valid_user_group_name(optarg, /* flags= */ 0))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid user name to bind: %s", optarg);

                        if (strv_extend(&arg_bind_user, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_BIND_USER_SHELL: {
                        bool copy = false;
                        char *sh = NULL;
                        r = parse_user_shell(optarg, &sh, &copy);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Invalid user shell to bind: %s", optarg);

                        free_and_replace(arg_bind_user_shell, sh);
                        arg_bind_user_shell_copy = copy;

                        break;
                }

                case ARG_BIND_USER_GROUP:
                        if (!valid_user_group_name(optarg, /* flags= */ 0))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid bind user auxiliary group name: %s", optarg);

                        if (strv_extend(&arg_bind_user_groups, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                case ARG_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        /* Drop duplicate --bind-user= and --bind-user-group= entries */
        strv_uniq(arg_bind_user);
        strv_uniq(arg_bind_user_groups);

        if (arg_bind_user_shell && strv_isempty(arg_bind_user))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot use --bind-user-shell= without --bind-user=");

        if (!strv_isempty(arg_bind_user_groups) && strv_isempty(arg_bind_user))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot use --bind-user-group= without --bind-user=");

        if (arg_ephemeral && arg_extra_drives.n_drives > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot use --ephemeral with --extra-drive=");

        if (argc > optind) {
                arg_kernel_cmdline_extra = strv_copy(argv + optind);
                if (!arg_kernel_cmdline_extra)
                        return log_oom();
        }

        return 1;
}

static int open_vsock(void) {
        static const union sockaddr_union bind_addr = {
                .vm.svm_family = AF_VSOCK,
                .vm.svm_cid = VMADDR_CID_ANY,
                .vm.svm_port = VMADDR_PORT_ANY,
        };

        _cleanup_close_ int vsock_fd = socket(AF_VSOCK, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (vsock_fd < 0)
                return log_error_errno(errno, "Failed to open AF_VSOCK socket: %m");

        if (bind(vsock_fd, &bind_addr.sa, sizeof(bind_addr.vm)) < 0)
                return log_error_errno(errno, "Failed to bind to VSOCK address %u:%u: %m", bind_addr.vm.svm_cid, bind_addr.vm.svm_port);

        if (listen(vsock_fd, SOMAXCONN_DELUXE) < 0)
                return log_error_errno(errno, "Failed to listen on VSOCK: %m");

        return TAKE_FD(vsock_fd);
}

typedef struct NotifyConnectionData {
        char buffer[NOTIFY_BUFFER_MAX+1];
        size_t full;
        int *exit_status;
} NotifyConnectionData;

static int read_vsock_notify(NotifyConnectionData *d, int fd) {
        int r;

        assert(d);
        assert(fd >= 0);

        for (;;) {
                assert(d->full < sizeof(d->buffer));

                ssize_t n = read(fd, d->buffer + d->full, sizeof(d->buffer) - d->full);
                if (n < 0) {
                        if (ERRNO_IS_TRANSIENT(errno))
                                return 0;

                        return log_error_errno(errno, "Failed to read notification message: %m");
                }
                if (n == 0) /* We hit EOF! Let's parse this */
                        break;

                if ((size_t) n >= sizeof(d->buffer) - d->full)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Received notify message exceeded maximum size.");

                d->full += n;
        }

        /* We reached EOF, now parse the thing */
        assert(d->full < sizeof(d->buffer));
        d->buffer[d->full] = 0;

        _cleanup_strv_free_ char **tags = strv_split(d->buffer, "\n\r");
        if (!tags)
                return log_oom();

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *j = strv_join(tags, " ");
                log_debug("Received notification message with tags: %s", strnull(j));
        }

        const char *status = strv_find_startswith(tags, "STATUS=");
        if (status)
                (void) sd_notifyf(/* unset_environment= */ false, "STATUS=VM running: %s", status);

        if (strv_contains(tags, "READY=1")) {
                r = sd_notify(/* unset_environment= */ false, "READY=1");
                if (r < 0)
                        log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");

                if (!status)
                        (void) sd_notifyf(/* unset_environment= */ false, "STATUS=VM running.");
        }

        const char *p = strv_find_startswith(tags, "EXIT_STATUS=");
        if (p) {
                uint8_t k = 0;
                r = safe_atou8(p, &k);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse exit status from %s, ignoring: %m", p);
                else
                        *d->exit_status = k;
        }

        return 1; /* done */
}

static int vmspawn_dispatch_notify_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        NotifyConnectionData *d = ASSERT_PTR(userdata);
        int r;

        assert(source);
        assert(fd >= 0);

        r = read_vsock_notify(d, fd);
        if (r != 0) {
                int q;

                /* If we are done or are seeing an error we'll turn off floating mode, which means the event
                 * loop itself won't keep the event source pinned anymore, and since no one else (hopefully!)
                 * keeps a reference anymore the whole thing will be released once we exit from this handler
                 * here. */

                q = sd_event_source_set_floating(source, false);
                if (q < 0)
                        log_warning_errno(q, "Failed to disable floating mode of event source, ignoring: %m");

                return r;
        }

        return 0;
}

static int vmspawn_dispatch_vsock_connections(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        _cleanup_close_ int conn_fd = -EBADF;
        sd_event *event;
        int r;

        assert(userdata);

        if (revents != EPOLLIN) {
                log_warning("Got unexpected poll event for VSOCK fd.");
                return 0;
        }

        conn_fd = accept4(fd, NULL, NULL, SOCK_CLOEXEC|SOCK_NONBLOCK);
        if (conn_fd < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                log_warning_errno(errno, "Failed to accept connection from VSOCK connection, ignoring: %m");
                return 0;
        }

        event = sd_event_source_get_event(source);
        if (!event)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Failed to retrieve event from event source, exiting task");

        _cleanup_free_ NotifyConnectionData *d = new(NotifyConnectionData, 1);
        if (!d)
                return log_oom();

        *d = (NotifyConnectionData) {
                .exit_status = userdata,
        };

        /* add a new floating task to read from the connection */
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_io(event, &s, conn_fd, EPOLLIN, vmspawn_dispatch_notify_fd, d);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate notify connection event source: %m");

        r = sd_event_source_set_io_fd_own(s, true);
        if (r < 0)
                return log_error_errno(r, "Failed to pass ownership of notify to event source: %m");
        TAKE_FD(conn_fd); /* conn_fd is now owned by the event loop so don't clean it up */

        r = sd_event_source_set_destroy_callback(s, free);
        if (r < 0)
                return log_error_errno(r, "Failed to set destroy callback on event source: %m");
        TAKE_PTR(d); /* The data object will now automatically be freed by the event source when it goes away */

        /* Finally, make sure the event loop pins the event source */
        r = sd_event_source_set_floating(s, true);
        if (r < 0)
                return log_error_errno(r, "Failed to set event source to floating mode: %m");

        (void) sd_event_source_set_description(s, "vmspawn-notify-socket-connection");

        return 0;
}

static int setup_notify_parent(sd_event *event, int fd, int *exit_status, sd_event_source **ret_notify_event_source) {
        int r;

        assert(event);
        assert(fd >= 0);
        assert(exit_status);
        assert(ret_notify_event_source);

        r = sd_event_add_io(event, ret_notify_event_source, fd, EPOLLIN, vmspawn_dispatch_vsock_connections, exit_status);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate notify socket event source: %m");

        (void) sd_event_source_set_description(*ret_notify_event_source, "vmspawn-notify-socket-listen");

        return 0;
}

static int bus_open_in_machine(sd_bus **ret, unsigned cid, unsigned port, const char *private_key_path) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *ssh_escaped = NULL, *bus_address = NULL;
        char port_str[DECIMAL_STR_MAX(unsigned)], cid_str[DECIMAL_STR_MAX(unsigned)];
        int r;

        assert(ret);
        assert(private_key_path);

        r = sd_bus_new(&bus);
        if (r < 0)
                return r;

        const char *ssh = secure_getenv("SYSTEMD_SSH") ?: "ssh";
        ssh_escaped = bus_address_escape(ssh);
        if (!ssh_escaped)
                return -ENOMEM;

        xsprintf(port_str, "%u", port);
        xsprintf(cid_str, "%u", cid);

        bus_address = strjoin(
                "unixexec:path=", ssh_escaped,
                /* -x: Disable X11 forwarding
                 * -T: Disable PTY allocation */
                ",argv1=-xT",
                ",argv2=-o,argv3=IdentitiesOnly yes",
                ",argv4=-o,argv5=IdentityFile=", private_key_path,
                ",argv6=-p,argv7=", port_str,
                ",argv8=--",
                ",argv9=root@vsock/", cid_str,
                ",argv10=systemd-stdio-bridge"
        );
        if (!bus_address)
                return -ENOMEM;

        free_and_replace(bus->address, bus_address);
        bus->bus_client = true;
        bus->trusted = true;
        bus->runtime_scope = RUNTIME_SCOPE_SYSTEM;
        bus->is_local = false;

        r = sd_bus_start(bus);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(bus);
        return 0;
}

static int shutdown_vm_graceful(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        ShutdownInfo *shutdown_info = ASSERT_PTR(userdata);
        SSHInfo *ssh_info = ASSERT_PTR(shutdown_info->ssh_info);
        int r;

        assert(s);
        assert(si);

        /* If we don't have the vsock address and the SSH key, go to fallback */
        if (ssh_info->cid == VMADDR_CID_ANY || !ssh_info->private_key_path)
                goto fallback;

        /*
         * In order we should try:
         * 1. PowerOff from logind respects inhibitors but might not be available
         * 2. PowerOff from systemd heavy handed but should always be available
         * 3. SIGKILL qemu (this waits for qemu to die still)
         * 4. kill ourselves by shutting down our event loop (this does not wait for qemu)
         */

        r = bus_open_in_machine(&bus, ssh_info->cid, ssh_info->port, ssh_info->private_key_path);
        if (r < 0) {
                log_warning_errno(r, "Failed to connect to VM to forward signal, ignoring: %m");
                goto fallback;
        }

        r = bus_call_method(bus, bus_login_mgr, "PowerOff", &error, /* ret_reply= */ NULL, "b", false);
        if (r >= 0) {
                log_info("Requested powering off VM through D-Bus.");
                return 0;
        }

        log_warning_errno(r, "Failed to shutdown VM via logind, ignoring: %s", bus_error_message(&error, r));
        sd_bus_error_free(&error);

        r = bus_call_method(bus, bus_systemd_mgr, "PowerOff", &error, /* ret_reply= */ NULL, /* types= */ NULL);
        if (r >= 0) {
                log_info("Requested powering off VM through D-Bus.");
                return 0;
        }

        log_warning_errno(r, "Failed to shutdown VM via systemd, ignoring: %s", bus_error_message(&error, r));

fallback:
        /* at this point SSH clearly isn't working so don't try it again */
        TAKE_STRUCT(*ssh_info);

        /* Backup method to shut down the VM when D-BUS access over SSH is not available */
        if (shutdown_info->pidref) {
                r = pidref_kill(shutdown_info->pidref, SIGKILL);
                if (r < 0)
                        log_warning_errno(r, "Failed to kill qemu, terminating: %m");
                else {
                        TAKE_PTR(shutdown_info->pidref);
                        log_info("Trying to halt qemu. Send SIGTERM again to trigger vmspawn to immediately terminate.");
                        return 0;
                }
        }

        return sd_event_exit(sd_event_source_get_event(s), 0);
}

static int on_child_exit(sd_event_source *s, const siginfo_t *si, void *userdata) {
        assert(si);

        /* Let's first do some logging about the exit status of the child. */

        int ret;
        if (si->si_code == CLD_EXITED) {
                if (si->si_status == EXIT_SUCCESS)
                        log_debug("Child process " PID_FMT " exited successfully.", si->si_pid);
                else
                        log_error("Child process " PID_FMT " died with a failure exit status %i.", si->si_pid, si->si_status);

                ret = si->si_status;
        } else if (si->si_code == CLD_KILLED)
                ret = log_error_errno(SYNTHETIC_ERRNO(EPROTO),
                                      "Child process " PID_FMT " was killed by signal %s.",
                                      si->si_pid, signal_to_string(si->si_status));
        else if (si->si_code == CLD_DUMPED)
                ret = log_error_errno(SYNTHETIC_ERRNO(EPROTO),
                                      "Child process " PID_FMT " dumped core by signal %s.",
                                      si->si_pid, signal_to_string(si->si_status));
        else
                ret = log_error_errno(SYNTHETIC_ERRNO(EPROTO),
                                      "Got unexpected exit code %i from child.",
                                      si->si_code);

        /* Regardless of whether the main qemu process or an auxiliary process died, let's exit either way
         * as it's very likely that the main qemu process won't be able to operate properly anymore if one
         * of the auxiliary processes died. */

        sd_event_exit(sd_event_source_get_event(s), ret);
        return 0;
}

static int cmdline_add_vsock(char ***cmdline, int vsock_fd) {
        int r;

        r = strv_extend(cmdline, "-smbios");
        if (r < 0)
                return r;

        union sockaddr_union addr;
        socklen_t addr_len = sizeof addr.vm;
        if (getsockname(vsock_fd, &addr.sa, &addr_len) < 0)
                return -errno;

        assert(addr_len >= sizeof addr.vm);
        assert(addr.vm.svm_family == AF_VSOCK);

        r = strv_extendf(cmdline, "type=11,value=io.systemd.credential:vmm.notify_socket=vsock-stream:%u:%u", (unsigned) VMADDR_CID_HOST, addr.vm.svm_port);
        if (r < 0)
                return r;

        return 0;
}

static int cmdline_add_kernel_cmdline(char ***cmdline, const char *kernel, const char *smbios_dir) {
        int r;

        assert(cmdline);

        if (strv_isempty(arg_kernel_cmdline_extra))
                return 0;

        _cleanup_free_ char *kcl = strv_join(arg_kernel_cmdline_extra, " ");
        if (!kcl)
                return log_oom();

        if (kernel) {
                if (strv_extend_many(cmdline, "-append", kcl) < 0)
                        return log_oom();
        } else {
                if (!ARCHITECTURE_SUPPORTS_SMBIOS) {
                        log_warning("Cannot append extra args to kernel cmdline, native architecture doesn't support SMBIOS, ignoring.");
                        return 0;
                }

                FOREACH_STRING(id, "io.systemd.stub.kernel-cmdline-extra", "io.systemd.boot.kernel-cmdline-extra") {
                        _cleanup_free_ char *p = path_join(smbios_dir, id);
                        if (!p)
                                return log_oom();

                        r = write_string_filef(
                                        p,
                                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE|WRITE_STRING_FILE_MODE_0600,
                                        "%s=%s", id, kcl);
                        if (r < 0)
                                return log_error_errno(r, "Failed to write smbios kernel command line to file: %m");

                        if (strv_extend(cmdline, "-smbios") < 0)
                                return log_oom();

                        if (strv_extend_joined(cmdline, "type=11,path=", p) < 0)
                                return log_oom();
                }
        }

        return 0;
}

static int cmdline_add_smbios11(char ***cmdline, const char* smbios_dir) {
        int r;

        assert(cmdline);

        if (strv_isempty(arg_smbios11))
                return 0;

        if (!ARCHITECTURE_SUPPORTS_SMBIOS) {
                log_warning("Cannot issue SMBIOS Type #11 strings, native architecture doesn't support SMBIOS, ignoring.");
                return 0;
        }

        STRV_FOREACH(i, arg_smbios11) {
                _cleanup_(unlink_and_freep) char *p = NULL;

                r = tempfn_random_child(smbios_dir, "smbios11", &p);
                if (r < 0)
                        return r;

                r = write_string_file(
                                p, *i,
                                WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE|WRITE_STRING_FILE_MODE_0600);
                if (r < 0)
                        return log_error_errno(r, "Failed to write smbios data to smbios file %s: %m", p);

                if (strv_extend(cmdline, "-smbios") < 0)
                        return log_oom();

                if (strv_extend_joined(cmdline, "type=11,path=", p) < 0)
                        return log_oom();

                p = mfree(p);
        }

        return 0;
}

static int start_tpm(
                const char *scope,
                const char *swtpm,
                const char *runtime_dir,
                const char *sd_socket_activate,
                char **ret_listen_address,
                PidRef *ret_pidref) {

        int r;

        assert(scope);
        assert(swtpm);
        assert(runtime_dir);

        _cleanup_free_ char *scope_prefix = NULL;
        r = unit_name_to_prefix(scope, &scope_prefix);
        if (r < 0)
                return log_error_errno(r, "Failed to strip .scope suffix from scope: %m");

        _cleanup_free_ char *listen_address = path_join(runtime_dir, "tpm.sock");
        if (!listen_address)
                return log_oom();

        _cleanup_free_ char *transient_state_dir = NULL;
        const char *state_dir;
        if (arg_tpm_state_path)
                state_dir = arg_tpm_state_path;
        else {
                _cleanup_free_ char *dirname = strjoin(scope_prefix, "-tpm");
                if (!dirname)
                        return log_oom();

                transient_state_dir = path_join(runtime_dir, dirname);
                if (!transient_state_dir)
                        return log_oom();

                state_dir = transient_state_dir;
        }

        r = mkdir_p(state_dir, 0700);
        if (r < 0)
                return log_error_errno(r, "Failed to create TPM state directory '%s': %m", state_dir);

        _cleanup_free_ char *swtpm_setup = NULL;
        r = find_executable("swtpm_setup", &swtpm_setup);
        if (r < 0)
                return log_error_errno(r, "Failed to find swtpm_setup binary: %m");

        /* Try passing --profile-name default-v2 first, in order to support RSA4096 pcrsig keys, which was
         * added in 0.11. */
        _cleanup_strv_free_ char **argv = strv_new(
                        swtpm_setup,
                        "--tpm-state", state_dir,
                        "--tpm2",
                        "--pcr-banks", "sha256",
                        "--not-overwrite",
                        "--profile-name", "default-v2");
        if (!argv)
                return log_oom();

        r = pidref_safe_fork("(swtpm-setup)", FORK_CLOSE_ALL_FDS|FORK_LOG|FORK_WAIT, /* ret= */ NULL);
        if (r == 0) {
                /* Child */
                execvp(argv[0], argv);
                log_error_errno(errno, "Failed to execute '%s': %m", argv[0]);
                _exit(EXIT_FAILURE);
        }
        if (r == -EPROTO) {
                /* If swtpm_setup fails, try again removing the default-v2 profile, as it might be an older
                 * version. */
                strv_remove(argv, "--profile-name");
                strv_remove(argv, "default-v2");

                r = pidref_safe_fork("(swtpm-setup)", FORK_CLOSE_ALL_FDS|FORK_LOG|FORK_WAIT, /* ret= */ NULL);
                if (r == 0) {
                        /* Child */
                        execvp(argv[0], argv);
                        log_error_errno(errno, "Failed to execute '%s': %m", argv[0]);
                        _exit(EXIT_FAILURE);
                }
        }
        if (r < 0)
                return log_error_errno(r, "Failed to run swtpm_setup: %m");

        strv_free(argv);
        argv = strv_new(sd_socket_activate, "--listen", listen_address, swtpm, "socket", "--tpm2", "--tpmstate");
        if (!argv)
                return log_oom();

        r = strv_extend_joined(&argv, "dir=", state_dir);
        if (r < 0)
                return log_oom();

        r = strv_extend_many(&argv, "--ctrl", "type=unixio,fd=3");
        if (r < 0)
                return log_oom();

        r = fork_notify(argv, ret_pidref);
        if (r < 0)
                return r;

        if (ret_listen_address)
                *ret_listen_address = TAKE_PTR(listen_address);

        return 0;
}

static int start_systemd_journal_remote(
                const char *scope,
                unsigned port,
                const char *sd_socket_activate,
                char **ret_listen_address,
                PidRef *ret_pidref) {

        int r;

        assert(scope);

        _cleanup_free_ char *scope_prefix = NULL;
        r = unit_name_to_prefix(scope, &scope_prefix);
        if (r < 0)
                return log_error_errno(r, "Failed to strip .scope suffix from scope: %m");

        _cleanup_free_ char *listen_address = NULL;
        if (asprintf(&listen_address, "vsock:2:%u", port) < 0)
                return log_oom();

        _cleanup_free_ char *sd_journal_remote = NULL;
        r = find_executable_full(
                        "systemd-journal-remote",
                        /* root= */ NULL,
                        STRV_MAKE(LIBEXECDIR),
                        /* use_path_envvar= */ true, /* systemd-journal-remote should be installed in
                                                        * LIBEXECDIR, but for supporting fancy setups. */
                        &sd_journal_remote,
                        /* ret_fd= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to find systemd-journal-remote binary: %m");

        _cleanup_strv_free_ char **argv = strv_new(
                        sd_socket_activate,
                        "--listen", listen_address,
                        sd_journal_remote,
                        "--output", arg_forward_journal,
                        "--split-mode", endswith(arg_forward_journal, ".journal") ? "none" : "host");
        if (!argv)
                return log_oom();

        r = fork_notify(argv, ret_pidref);
        if (r < 0)
                return r;

        if (ret_listen_address)
                *ret_listen_address = TAKE_PTR(listen_address);

        return 0;
}

static int discover_root(char **ret) {
        int r;
        _cleanup_(dissected_image_unrefp) DissectedImage *image = NULL;
        _cleanup_free_ char *root = NULL;

        assert(ret);

        r = dissect_image_file_and_warn(
                        arg_image,
                        /* verity= */ NULL,
                        /* mount_options= */ NULL,
                        /* image_policy= */ NULL,
                        /* image_filter= */ NULL,
                        /* flags= */ 0,
                        &image);
        if (r < 0)
                return r;

        if (image->partitions[PARTITION_ROOT].found)
                root = strjoin("root=PARTUUID=", SD_ID128_TO_UUID_STRING(image->partitions[PARTITION_ROOT].uuid));
        else if (image->partitions[PARTITION_USR].found)
                root = strjoin("mount.usr=PARTUUID=", SD_ID128_TO_UUID_STRING(image->partitions[PARTITION_USR].uuid));
        else
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Cannot perform a direct kernel boot without a root or usr partition, refusing");

        if (!root)
                return log_oom();

        *ret = TAKE_PTR(root);
        return 0;
}

static int find_virtiofsd(char **ret) {
        int r;
        _cleanup_free_ char *virtiofsd = NULL;

        assert(ret);

        r = find_executable("virtiofsd", &virtiofsd);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Error while searching for virtiofsd: %m");

        if (!virtiofsd) {
                FOREACH_STRING(file, "/usr/libexec/virtiofsd", "/usr/lib/virtiofsd") {
                        if (access(file, X_OK) >= 0) {
                                virtiofsd = strdup(file);
                                if (!virtiofsd)
                                        return log_oom();
                                break;
                        }

                        if (!IN_SET(errno, ENOENT, EACCES))
                                return log_error_errno(errno, "Error while searching for virtiofsd: %m");
                }
        }

        if (!virtiofsd)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Failed to find virtiofsd binary.");

        *ret = TAKE_PTR(virtiofsd);
        return 0;
}

static int start_virtiofsd(
                const char *scope,
                const char *directory,
                uid_t source_uid,
                uid_t target_uid,
                uid_t uid_range,
                const char *runtime_dir,
                const char *sd_socket_activate,
                char **ret_listen_address,
                PidRef *ret_pidref) {

        int r;

        assert(scope);
        assert(directory);
        assert(runtime_dir);

        _cleanup_free_ char *virtiofsd = NULL;
        r = find_virtiofsd(&virtiofsd);
        if (r < 0)
                return r;

        _cleanup_free_ char *scope_prefix = NULL;
        r = unit_name_to_prefix(scope, &scope_prefix);
        if (r < 0)
                return log_error_errno(r, "Failed to strip .scope suffix from scope: %m");

        _cleanup_free_ char *listen_address = NULL;
        if (asprintf(&listen_address, "%s/sock-%"PRIx64, runtime_dir, random_u64()) < 0)
                return log_oom();

        /* QEMU doesn't support submounts so don't announce them */
        _cleanup_strv_free_ char **argv = strv_new(
                        sd_socket_activate,
                        "--listen", listen_address,
                        virtiofsd,
                        "--shared-dir", directory,
                        "--xattr",
                        "--fd", "3",
                        "--no-announce-submounts");
        if (!argv)
                return log_oom();

        if (source_uid != UID_INVALID && target_uid != UID_INVALID && uid_range != UID_INVALID) {
                r = strv_extend(&argv, "--translate-uid");
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&argv, "map:" UID_FMT ":" UID_FMT ":" UID_FMT, target_uid, source_uid, uid_range);
                if (r < 0)
                        return log_oom();

                r = strv_extend(&argv, "--translate-gid");
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&argv, "map:" GID_FMT ":" GID_FMT ":" GID_FMT, target_uid, source_uid, uid_range);
                if (r < 0)
                        return log_oom();
        }

        r = fork_notify(argv, ret_pidref);
        if (r < 0)
                return r;

        if (ret_listen_address)
                *ret_listen_address = TAKE_PTR(listen_address);

        return 0;
}

static int bind_user_setup(
                const MachineBindUserContext *context,
                MachineCredentialContext *credentials,
                RuntimeMountContext *mounts) {

        int r;

        assert(credentials);
        assert(mounts);

        if (!context)
                return 0;

        FOREACH_ARRAY(bind_user, context->data, context->n_data) {
                _cleanup_free_ char *formatted = NULL;
                r = sd_json_variant_format(bind_user->payload_user->json, SD_JSON_FORMAT_NEWLINE, &formatted);
                if (r < 0)
                        return log_error_errno(r, "Failed to format JSON user record: %m");

                _cleanup_free_ char *cred = strjoin("userdb.transient.user.", bind_user->payload_user->user_name);
                if (!cred)
                        return log_oom();

                r = machine_credential_add(credentials, cred, formatted, SIZE_MAX);
                if (r < 0)
                        return r;

                formatted = mfree(formatted);
                r = sd_json_variant_format(bind_user->payload_group->json, SD_JSON_FORMAT_NEWLINE, &formatted);
                if (r < 0)
                        return log_error_errno(r, "Failed to format JSON group record: %m");

                free(cred);
                cred = strjoin("userdb.transient.group.", bind_user->payload_group->group_name);
                if (!cred)
                        return log_oom();

                r = machine_credential_add(credentials, cred, formatted, SIZE_MAX);
                if (r < 0)
                        return r;

                _cleanup_(runtime_mount_done) RuntimeMount mount = {
                        .source = strdup(user_record_home_directory(bind_user->host_user)),
                        .source_uid = bind_user->host_user->uid,
                        .target = strdup(user_record_home_directory(bind_user->payload_user)),
                        .target_uid = bind_user->payload_user->uid,
                };
                if (!mount.source || !mount.target)
                        return log_oom();

                if (!GREEDY_REALLOC(mounts->mounts, mounts->n_mounts + 1))
                        return log_oom();

                mounts->mounts[mounts->n_mounts++] = TAKE_STRUCT(mount);
        }

        return 0;
}

static int kernel_cmdline_maybe_append_root(void) {
        int r;
        bool cmdline_contains_root = strv_find_startswith(arg_kernel_cmdline_extra, "root=")
                        || strv_find_startswith(arg_kernel_cmdline_extra, "mount.usr=");

        if (!cmdline_contains_root) {
                _cleanup_free_ char *root = NULL;

                r = discover_root(&root);
                if (r < 0)
                        return r;

                log_debug("Determined root file system %s from dissected image", root);

                r = strv_consume(&arg_kernel_cmdline_extra, TAKE_PTR(root));
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int discover_boot_entry(const char *root, char **ret_linux, char ***ret_initrds) {
        _cleanup_(boot_config_free) BootConfig config = BOOT_CONFIG_NULL;
        _cleanup_free_ char *esp_path = NULL, *xbootldr_path = NULL;
        int r;

        assert(root);
        assert(ret_linux);
        assert(ret_initrds);

        esp_path = path_join(root, "efi");
        if (!esp_path)
                return log_oom();

        xbootldr_path = path_join(root, "boot");
        if (!xbootldr_path)
                return log_oom();

        r = boot_config_load(&config, esp_path, xbootldr_path);
        if (r < 0)
                return r;

        r = boot_config_select_special_entries(&config, /* skip_efivars= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to find special boot config entries: %m");

        const BootEntry *boot_entry = boot_config_default_entry(&config);

        if (boot_entry && !IN_SET(boot_entry->type, BOOT_ENTRY_TYPE1, BOOT_ENTRY_TYPE2))
                boot_entry = NULL;

        /* If we cannot determine a default entry search for UKIs (Type #2 EFI Unified Kernel Images)
         * then .conf files (Type #1 Boot Loader Specification Entries).
         * https://uapi-group.org/specifications/specs/boot_loader_specification */
        if (!boot_entry)
                FOREACH_ARRAY(entry, config.entries, config.n_entries)
                        if (entry->type == BOOT_ENTRY_TYPE2) { /* UKI */
                                boot_entry = entry;
                                break;
                        }

        if (!boot_entry)
                FOREACH_ARRAY(entry, config.entries, config.n_entries)
                        if (entry->type == BOOT_ENTRY_TYPE1) { /* .conf */
                                boot_entry = entry;
                                break;
                        }

        if (!boot_entry)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Failed to discover any boot entries.");

        log_debug("Discovered boot entry %s (%s)", boot_entry->id, boot_entry_type_description_to_string(boot_entry->type));

        _cleanup_free_ char *linux_kernel = NULL;
        _cleanup_strv_free_ char **initrds = NULL;
        if (boot_entry->type == BOOT_ENTRY_TYPE2) { /* UKI */
                linux_kernel = path_join(boot_entry->root, boot_entry->kernel);
                if (!linux_kernel)
                        return log_oom();
        } else if (boot_entry->type == BOOT_ENTRY_TYPE1) { /* .conf */
                linux_kernel = path_join(boot_entry->root, boot_entry->kernel);
                if (!linux_kernel)
                        return log_oom();

                STRV_FOREACH(initrd, boot_entry->initrd) {
                        _cleanup_free_ char *initrd_path = path_join(boot_entry->root, *initrd);
                        if (!initrd_path)
                                return log_oom();

                        r = strv_consume(&initrds, TAKE_PTR(initrd_path));
                        if (r < 0)
                                return log_oom();
                }
        } else
                assert_not_reached();

        *ret_linux = TAKE_PTR(linux_kernel);
        *ret_initrds = TAKE_PTR(initrds);

        return 0;
}

static int merge_initrds(char **ret) {
        _cleanup_(rm_rf_physical_and_freep) char *merged_initrd = NULL;
        _cleanup_close_ int ofd = -EBADF;
        int r;

        assert(ret);

        r = tempfn_random_child(NULL, "vmspawn-initrd-", &merged_initrd);
        if (r < 0)
                return log_error_errno(r, "Failed to create temporary file: %m");

        ofd = open(merged_initrd, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600);
        if (ofd < 0)
                return log_error_errno(errno, "Failed to create regular file %s: %m", merged_initrd);

        STRV_FOREACH(i, arg_initrds) {
                _cleanup_close_ int ifd = -EBADF;
                off_t off, to_seek;

                off = lseek(ofd, 0, SEEK_CUR);
                if (off < 0)
                        return log_error_errno(errno, "Failed to get file offset of %s: %m", merged_initrd);

                to_seek = (4 - (off % 4)) % 4;

                /* seek to assure 4 byte alignment for each initrd */
                if (to_seek != 0 && lseek(ofd, to_seek, SEEK_CUR) < 0)
                        return log_error_errno(errno, "Failed to seek %s: %m", merged_initrd);

                ifd = open(*i, O_RDONLY|O_CLOEXEC);
                if (ifd < 0)
                        return log_error_errno(errno, "Failed to open %s: %m", *i);

                r = copy_bytes(ifd, ofd, UINT64_MAX, COPY_REFLINK);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy bytes from %s to %s: %m", *i, merged_initrd);
        }

        *ret = TAKE_PTR(merged_initrd);
        return 0;
}

static int generate_ssh_keypair(const char *key_path, const char *key_type) {
        _cleanup_free_ char *ssh_keygen = NULL;
        _cleanup_strv_free_ char **cmdline = NULL;
        int r;

        assert(key_path);

        r = find_executable("ssh-keygen", &ssh_keygen);
        if (r < 0)
                return log_error_errno(r, "Failed to find ssh-keygen: %m");

        cmdline = strv_new(ssh_keygen, "-f", key_path, /* don't encrypt the key */ "-N", "");
        if (!cmdline)
                return log_oom();

        if (key_type) {
                r = strv_extend_many(&cmdline, "-t", key_type);
                if (r < 0)
                        return log_oom();
        }

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *joined = quote_command_line(cmdline, SHELL_ESCAPE_EMPTY);
                if (!joined)
                        return log_oom();

                log_debug("Executing: %s", joined);
        }

        r = pidref_safe_fork_full(
                        ssh_keygen,
                        (int[]) { -EBADF, -EBADF, STDERR_FILENO },
                        /* except_fds= */ NULL, /* n_except_fds= */ 0,
                        FORK_WAIT|FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE|FORK_REARRANGE_STDIO|FORK_REOPEN_LOG,
                        /* ret= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                execv(ssh_keygen, cmdline);
                log_error_errno(errno, "Failed to execve %s: %m", ssh_keygen);
                _exit(EXIT_FAILURE);
        }

        return 0;
}

static int grow_image(const char *path, uint64_t size) {
        int r;

        assert(path);

        if (size == 0)
                return 0;

        /* Round up to multiple of 4K */
        size = DIV_ROUND_UP(size, 4096);
        if (size > UINT64_MAX / 4096)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified file size too large, refusing.");
        size *= 4096;

        _cleanup_close_ int fd = xopenat_full(AT_FDCWD, path, O_RDWR|O_CLOEXEC, XO_REGULAR, /* mode= */ 0);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open image file '%s': %m", path);

        struct stat st;
        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat '%s': %m", path);
        if ((uint64_t) st.st_size >= size) {
                log_debug("Not growing image '%s' to %s, size already at %s.", path,
                          FORMAT_BYTES(size), FORMAT_BYTES(st.st_size));
                return 0;
        }

        if (ftruncate(fd, size) < 0)
                return log_error_errno(errno, "Failed to grow image file '%s' from %s to %s: %m", path,
                                       FORMAT_BYTES(st.st_size), FORMAT_BYTES(size));

        r = fsync_full(fd);
        if (r < 0)
                return log_error_errno(r, "Failed to sync image file '%s' after growing to %s: %m", path, FORMAT_BYTES(size));

        if (!arg_quiet)
                log_info("Image file '%s' successfully grown from %s to %s.", path, FORMAT_BYTES(st.st_size), FORMAT_BYTES(size));

        return 1;
}

static int on_request_stop(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        assert(m);

        log_info("VM termination requested. Exiting.");
        sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), 0);

        return 0;
}

static int run_virtual_machine(int kvm_device_fd, int vhost_device_fd) {
        _cleanup_(ovmf_config_freep) OvmfConfig *ovmf_config = NULL;
        _cleanup_free_ char *qemu_binary = NULL, *mem = NULL, *kernel = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *ssh_private_key_path = NULL, *ssh_public_key_path = NULL;
        _cleanup_(rm_rf_subvolume_and_freep) char *snapshot_directory = NULL;
        _cleanup_(release_lock_file) LockFile tree_global_lock = LOCK_FILE_INIT, tree_local_lock = LOCK_FILE_INIT;
        _cleanup_close_ int notify_sock_fd = -EBADF;
        _cleanup_strv_free_ char **cmdline = NULL;
        _cleanup_free_ int *pass_fds = NULL;
        sd_event_source **children = NULL;
        size_t n_children = 0, n_pass_fds = 0;
        const char *accel;
        int r;

        CLEANUP_ARRAY(children, n_children, fork_notify_terminate_many);

        polkit_agent_open();

        /* Registration always happens on the system bus */
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *system_bus = NULL;
        if (arg_register || arg_runtime_scope == RUNTIME_SCOPE_SYSTEM) {
                r = sd_bus_default_system(&system_bus);
                if (r < 0)
                        return log_error_errno(r, "Failed to open system bus: %m");

                r = sd_bus_set_close_on_exit(system_bus, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to disable close-on-exit behaviour: %m");

                (void) sd_bus_set_allow_interactive_authorization(system_bus, arg_ask_password);
        }

        /* Scope allocation happens on the user bus if we are unpriv, otherwise system bus. */
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *user_bus = NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *runtime_bus = NULL;
        if (arg_runtime_scope == RUNTIME_SCOPE_SYSTEM)
                runtime_bus = sd_bus_ref(system_bus);
        else {
                r = sd_bus_default_user(&user_bus);
                if (r < 0)
                        return log_error_errno(r, "Failed to open system bus: %m");

                r = sd_bus_set_close_on_exit(user_bus, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to disable close-on-exit behaviour: %m");

                runtime_bus = sd_bus_ref(user_bus);
        }

        bool use_kvm = arg_kvm > 0;
        if (arg_kvm < 0) {
                r = qemu_check_kvm_support();
                if (r < 0)
                        return log_error_errno(r, "Failed to check for KVM support: %m");
                use_kvm = r;
        }

        if (arg_firmware)
                r = load_ovmf_config(arg_firmware, &ovmf_config);
        else
                r = find_ovmf_config(arg_secure_boot, &ovmf_config);
        if (r < 0)
                return log_error_errno(r, "Failed to find OVMF config: %m");

        if (arg_secure_boot > 0 && !ovmf_config->supports_sb) {
                assert(arg_firmware);

                return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE),
                                       "Secure Boot requested, but supplied OVMF firmware blob doesn't support it.");
        }

        if (arg_secure_boot < 0)
                log_debug("Using OVMF firmware %s Secure Boot support.", ovmf_config->supports_sb ? "with" : "without");

        _cleanup_(machine_bind_user_context_freep) MachineBindUserContext *bind_user_context = NULL;
        r = machine_bind_user_prepare(
                        /* directory= */ NULL,
                        arg_bind_user,
                        arg_bind_user_shell,
                        arg_bind_user_shell_copy,
                        "/run/vmhost/home",
                        arg_bind_user_groups,
                        &bind_user_context);
        if (r < 0)
                return r;

        r = bind_user_setup(bind_user_context, &arg_credentials, &arg_runtime_mounts);
        if (r < 0)
                return r;

        _cleanup_free_ char *machine = NULL;
        const char *shm = arg_directory || arg_runtime_mounts.n_mounts != 0 ? ",memory-backend=mem" : "";
        const char *hpet = ARCHITECTURE_SUPPORTS_HPET ? ",hpet=off" : "";
        if (ARCHITECTURE_SUPPORTS_SMM)
                machine = strjoin("type=" QEMU_MACHINE_TYPE ",smm=", on_off(ovmf_config->supports_sb), shm, hpet);
        else
                machine = strjoin("type=" QEMU_MACHINE_TYPE, shm, hpet);
        if (!machine)
                return log_oom();

        if (arg_linux) {
                kernel = strdup(arg_linux);
                if (!kernel)
                        return log_oom();
        } else if (arg_directory) {
                /* a kernel is required for directory type images so attempt to locate a UKI under /boot and /efi */
                r = discover_boot_entry(arg_directory, &kernel, &arg_initrds);
                if (r < 0)
                        return log_error_errno(r, "Failed to locate UKI in directory type image, please specify one with --linux=.");

                log_debug("Discovered UKI image at %s", kernel);
        }

        r = find_qemu_binary(&qemu_binary);
        if (r == -EOPNOTSUPP)
                return log_error_errno(r, "Native architecture is not supported by qemu.");
        if (r < 0)
                return log_error_errno(r, "Failed to find QEMU binary: %m");

        if (asprintf(&mem, "%" PRIu64 "M", DIV_ROUND_UP(arg_ram, U64_MB)) < 0)
                return log_oom();

        cmdline = strv_new(
                qemu_binary,
                "-machine", machine,
                "-smp", arg_cpus ?: "1",
                "-m", mem,
                "-object", "rng-random,filename=/dev/urandom,id=rng0",
                "-device", "virtio-rng-pci,rng=rng0,id=rng-device0",
                "-device", "virtio-balloon,free-page-reporting=on"
        );
        if (!cmdline)
                return log_oom();

        if (!sd_id128_is_null(arg_uuid))
                if (strv_extend_many(&cmdline, "-uuid", SD_ID128_TO_UUID_STRING(arg_uuid)) < 0)
                        return log_oom();

        if (ARCHITECTURE_SUPPORTS_VMGENID) {
                /* Derive a vmgenid automatically from the invocation ID, in a deterministic way. */
                sd_id128_t vmgenid;
                r = sd_id128_get_invocation_app_specific(SD_ID128_MAKE(bd,84,6d,e3,e4,7d,4b,6c,a6,85,4a,87,0f,3c,a3,a0), &vmgenid);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get invocation ID, making up randomized vmgenid: %m");

                        r = sd_id128_randomize(&vmgenid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to make up randomized vmgenid: %m");
                }

                if (strv_extend(&cmdline, "-device") < 0)
                        return log_oom();

                if (strv_extendf(&cmdline, "vmgenid,guid=" SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(vmgenid)) < 0)
                        return log_oom();
        }

        /* if we are going to be starting any units with state then create our runtime dir */
        _cleanup_free_ char *runtime_dir = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir_destroy = NULL;
        if (arg_tpm != 0 || arg_directory || arg_runtime_mounts.n_mounts != 0 || arg_pass_ssh_key) {
                _cleanup_free_ char *subdir = NULL;

                if (asprintf(&subdir, "systemd/vmspawn.%" PRIx64, random_u64()) < 0)
                        return log_oom();

                r = runtime_directory(arg_runtime_scope, subdir, &runtime_dir);
                if (r < 0)
                        return log_error_errno(r, "Failed to lookup runtime directory: %m");
                if (r > 0) { /* We need to create our own runtime dir */
                        r = mkdir_p(runtime_dir, 0755);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create runtime directory '%s': %m", runtime_dir);

                        /* We created this, hence also destroy it */
                        runtime_dir_destroy = TAKE_PTR(runtime_dir);

                        runtime_dir = strdup(runtime_dir_destroy);
                        if (!runtime_dir)
                                return log_oom();
                }

                log_debug("Using runtime directory: %s", runtime_dir);
        }

        _cleanup_close_ int delegate_userns_fd = -EBADF, tap_fd = -EBADF;
        if (arg_network_stack == NETWORK_STACK_TAP) {
                if (have_effective_cap(CAP_NET_ADMIN) <= 0) {
                        delegate_userns_fd = userns_acquire_self_root();
                        if (delegate_userns_fd < 0)
                                return log_error_errno(delegate_userns_fd, "Failed to acquire userns: %m");

                        _cleanup_free_ char *userns_name = NULL;
                        if (asprintf(&userns_name, "vmspawn-" PID_FMT "-%s", getpid_cached(), arg_machine) < 0)
                                return log_oom();

                        _cleanup_(sd_varlink_unrefp) sd_varlink *nsresource_link = NULL;
                        r = nsresource_connect(&nsresource_link);
                        if (r < 0)
                                return log_error_errno(r, "Failed to connect to nsresourced: %m");

                        r = nsresource_register_userns(nsresource_link, userns_name, delegate_userns_fd);
                        if (r < 0)
                                return log_error_errno(r, "Failed to register user namespace with systemd-nsresourced: %m");

                        tap_fd = nsresource_add_netif_tap(nsresource_link, delegate_userns_fd, /* ret_host_ifname= */ NULL);
                        if (tap_fd < 0)
                                return log_error_errno(tap_fd, "Failed to allocate network tap device: %m");

                        r = strv_extend(&cmdline, "-nic");
                        if (r < 0)
                                return log_oom();

                        r = strv_extendf(&cmdline, "tap,fd=%i,model=virtio-net-pci", tap_fd);
                        if (r < 0)
                                return log_oom();

                        if (!GREEDY_REALLOC(pass_fds, n_pass_fds + 1))
                                return log_oom();

                        pass_fds[n_pass_fds++] = tap_fd;
                } else {
                        _cleanup_free_ char *tap_name = NULL;
                        struct ether_addr mac_vm = {};

                        tap_name = strjoin("vt-", arg_machine);
                        if (!tap_name)
                                return log_oom();

                        (void) net_shorten_ifname(tap_name, /* check_naming_scheme= */ false);

                        if (ether_addr_is_null(&arg_network_provided_mac)){
                                r = net_generate_mac(arg_machine, &mac_vm, VM_TAP_HASH_KEY, 0);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to generate predictable MAC address for VM side: %m");
                        } else
                                mac_vm = arg_network_provided_mac;

                        r = strv_extend(&cmdline, "-nic");
                        if (r < 0)
                                return log_oom();

                        r = strv_extendf(&cmdline, "tap,ifname=%s,script=no,downscript=no,model=virtio-net-pci,mac=%s", tap_name, ETHER_ADDR_TO_STR(&mac_vm));
                        if (r < 0)
                                return log_oom();
                }
        } else if (arg_network_stack == NETWORK_STACK_USER)
                r = strv_extend_many(&cmdline, "-nic", "user,model=virtio-net-pci");
        else
                r = strv_extend_many(&cmdline, "-nic", "none");
        if (r < 0)
                return log_oom();

        /* A shared memory backend might increase ram usage so only add one if actually necessary for virtiofsd. */
        if (arg_directory || arg_runtime_mounts.n_mounts != 0) {
                r = strv_extend(&cmdline, "-object");
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&cmdline, "memory-backend-memfd,id=mem,size=%s,share=on", mem);
                if (r < 0)
                        return log_oom();
        }

        bool use_vsock = arg_vsock > 0 && ARCHITECTURE_SUPPORTS_SMBIOS;
        if (arg_vsock < 0) {
                r = qemu_check_vsock_support();
                if (r < 0)
                        return log_error_errno(r, "Failed to check for VSOCK support: %m");

                use_vsock = r;
        }

        if (!use_kvm && kvm_device_fd >= 0) {
                log_warning("KVM is disabled but fd for /dev/kvm was passed, closing fd and ignoring");
                kvm_device_fd = safe_close(kvm_device_fd);
        }

        if (use_kvm && kvm_device_fd >= 0) {
                /* /dev/fdset/1 is magic string to tell qemu where to find the fd for /dev/kvm
                 * we use this so that we can take a fd to /dev/kvm and then give qemu that fd */
                accel = "kvm,device=/dev/fdset/1";

                r = strv_extend(&cmdline, "--add-fd");
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&cmdline, "fd=%d,set=1,opaque=/dev/kvm", kvm_device_fd);
                if (r < 0)
                        return log_oom();

                if (!GREEDY_REALLOC(pass_fds, n_pass_fds + 1))
                        return log_oom();

                pass_fds[n_pass_fds++] = kvm_device_fd;
        } else if (use_kvm)
                accel = "kvm";
        else
                accel = "tcg";

        r = strv_extend_many(&cmdline, "-accel", accel);
        if (r < 0)
                return log_oom();

        _cleanup_close_ int child_vsock_fd = -EBADF;
        unsigned child_cid = arg_vsock_cid;
        if (use_vsock) {
                int device_fd = vhost_device_fd;

                if (device_fd < 0) {
                        child_vsock_fd = open("/dev/vhost-vsock", O_RDWR|O_CLOEXEC);
                        if (child_vsock_fd < 0)
                                return log_error_errno(errno, "Failed to open /dev/vhost-vsock as read/write: %m");

                        device_fd = child_vsock_fd;
                }

                r = vsock_fix_child_cid(device_fd, &child_cid, arg_machine);
                if (r < 0)
                        return log_error_errno(r, "Failed to fix CID for the guest VSOCK socket: %m");

                r = strv_extend(&cmdline, "-device");
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&cmdline, "vhost-vsock-pci,guest-cid=%u,vhostfd=%d", child_cid, device_fd);
                if (r < 0)
                        return log_oom();

                if (!GREEDY_REALLOC(pass_fds, n_pass_fds + 1))
                        return log_oom();

                pass_fds[n_pass_fds++] = device_fd;
        }

        r = strv_extend_many(&cmdline, "-cpu",
#ifdef __x86_64__
                             "max,hv_relaxed,hv-vapic,hv-time"
#else
                             "max"
#endif
        );
        if (r < 0)
                return log_oom();

        _cleanup_close_ int master = -EBADF;
        PTYForwardFlags ptyfwd_flags = 0;
        switch (arg_console_mode) {

        case CONSOLE_READ_ONLY:
                ptyfwd_flags |= PTY_FORWARD_READ_ONLY;

                _fallthrough_;

        case CONSOLE_INTERACTIVE:  {
                _cleanup_free_ char *pty_path = NULL;

                master = openpt_allocate(O_RDWR|O_NONBLOCK, &pty_path);
                if (master < 0)
                        return log_error_errno(master, "Failed to setup pty: %m");

                if (strv_extend_many(
                                &cmdline,
                                "-nographic",
                                "-nodefaults",
                                "-device", "virtio-serial-pci,id=vmspawn-virtio-serial-pci",
                                "-chardev") < 0)
                        return log_oom();

                if (strv_extend_joined(&cmdline, "serial,id=console,path=", pty_path) < 0)
                        return log_oom();

                r = strv_extend_many(
                                &cmdline,
                                "-device", "virtconsole,chardev=console");
                break;
        }

        case CONSOLE_GUI:
                /* Enable support for the qemu guest agent for clipboard sharing, resolution scaling, etc. */
                r = strv_extend_many(
                                &cmdline,
                                "-vga",
                                "virtio",
                                "-device", "virtio-serial",
                                "-chardev", "spicevmc,id=vdagent,debug=0,name=vdagent",
                                "-device", "virtserialport,chardev=vdagent,name=org.qemu.guest_agent.0");
                break;

        case CONSOLE_NATIVE:
                r = strv_extend_many(
                                &cmdline,
                                "-nographic",
                                "-nodefaults",
                                "-chardev", "stdio,mux=on,id=console,signal=off",
                                "-device", "virtio-serial-pci,id=vmspawn-virtio-serial-pci",
                                "-device", "virtconsole,chardev=console",
                                "-mon", "console");
                break;

        default:
                assert_not_reached();
        }
        if (r < 0)
                return log_oom();

        r = strv_extend(&cmdline, "-drive");
        if (r < 0)
                return log_oom();

        _cleanup_free_ char *escaped_ovmf_config_path = escape_qemu_value(ovmf_config->path);
        if (!escaped_ovmf_config_path)
                return log_oom();

        r = strv_extendf(&cmdline, "if=pflash,format=%s,readonly=on,file=%s", ovmf_config_format(ovmf_config), escaped_ovmf_config_path);
        if (r < 0)
                return log_oom();

        _cleanup_(unlink_and_freep) char *ovmf_vars_to = NULL;
        if (ovmf_config->supports_sb) {
                const char *ovmf_vars_from = ovmf_config->vars;
                _cleanup_free_ char *escaped_ovmf_vars_to = NULL;
                _cleanup_close_ int source_fd = -EBADF, target_fd = -EBADF;

                r = tempfn_random_child(NULL, "vmspawn-", &ovmf_vars_to);
                if (r < 0)
                        return r;

                source_fd = open(ovmf_vars_from, O_RDONLY|O_CLOEXEC);
                if (source_fd < 0)
                        return log_error_errno(source_fd, "Failed to open OVMF vars file %s: %m", ovmf_vars_from);

                target_fd = open(ovmf_vars_to, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600);
                if (target_fd < 0)
                        return log_error_errno(errno, "Failed to create regular file for OVMF vars at %s: %m", ovmf_vars_to);

                r = copy_bytes(source_fd, target_fd, UINT64_MAX, COPY_REFLINK);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy bytes from %s to %s: %m", ovmf_vars_from, ovmf_vars_to);

                /* This isn't always available so don't raise an error if it fails */
                (void) copy_times(source_fd, target_fd, 0);

                r = strv_extend_many(
                                &cmdline,
                                "-global", "ICH9-LPC.disable_s3=1",
                                "-global", "driver=cfi.pflash01,property=secure,value=on",
                                "-drive");
                if (r < 0)
                        return log_oom();

                escaped_ovmf_vars_to = escape_qemu_value(ovmf_vars_to);
                if (!escaped_ovmf_vars_to)
                        return log_oom();

                r = strv_extendf(&cmdline, "file=%s,if=pflash,format=%s", escaped_ovmf_vars_to, ovmf_config_format(ovmf_config));
                if (r < 0)
                        return log_oom();
        }

        if (kernel) {
                r = strv_extend_many(&cmdline, "-kernel", kernel);
                if (r < 0)
                        return log_oom();

                /* We can't rely on gpt-auto-generator when direct kernel booting so synthesize a root=
                 * kernel argument instead. */
                if (arg_image) {
                        r = kernel_cmdline_maybe_append_root();
                        if (r < 0)
                                return r;
                }
        }

        if (arg_image) {
                assert(!arg_directory);

                if (arg_image_format == IMAGE_FORMAT_QCOW2) {
                        r = verify_regular_at(AT_FDCWD, arg_image, /* follow= */ true);
                        if (r < 0)
                                return log_error_errno(r,
                                                       "Block device '%s' cannot be used with 'qcow2' format, only 'raw' is supported: %m",
                                                       arg_image);
                }

                if (strv_extend(&cmdline, "-drive") < 0)
                        return log_oom();

                _cleanup_free_ char *escaped_image = escape_qemu_value(arg_image);
                if (!escaped_image)
                        return log_oom();

                if (strv_extendf(&cmdline, "if=none,id=vmspawn,file=%s,format=%s,discard=%s,snapshot=%s",
                                 escaped_image, image_format_to_string(arg_image_format), on_off(arg_discard_disk), on_off(arg_ephemeral)) < 0)
                        return log_oom();

                _cleanup_free_ char *image_fn = NULL;
                r = path_extract_filename(arg_image, &image_fn);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from path '%s': %m", image_fn);

                _cleanup_free_ char *escaped_image_fn = escape_qemu_value(image_fn);
                if (!escaped_image_fn)
                        return log_oom();

                if (strv_extend(&cmdline, "-device") < 0)
                        return log_oom();

                if (strv_extend_joined(&cmdline, "virtio-blk-pci,drive=vmspawn,bootindex=1,serial=", escaped_image_fn) < 0)
                        return log_oom();

                r = grow_image(arg_image, arg_grow_image);
                if (r < 0)
                        return r;
        }

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        r = sd_event_new(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get default event loop: %m");

        (void) sd_event_set_watchdog(event, true);

        _cleanup_free_ char *unit = NULL;
        r = unit_name_mangle_with_suffix(arg_machine, "as machine name", /* flags= */ 0, ".scope", &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle scope name: %m");

        _cleanup_free_ char *sd_socket_activate = NULL;
        r = find_executable("systemd-socket-activate", &sd_socket_activate);
        if (r < 0)
                return log_error_errno(r, "Failed to find systemd-socket-activate binary: %m");

        if (arg_directory) {
                _cleanup_free_ char *listen_address = NULL;
                _cleanup_(fork_notify_terminate) PidRef child = PIDREF_NULL;

                if (!GREEDY_REALLOC(children, n_children + 1))
                        return log_oom();

                if (arg_ephemeral) {
                        r = create_ephemeral_snapshot(arg_directory,
                                                      arg_runtime_scope,
                                                      /* read-only */ false,
                                                      &tree_global_lock,
                                                      &tree_local_lock,
                                                      &snapshot_directory);
                        if (r < 0)
                                return r;

                        arg_directory = strdup(snapshot_directory);
                        if (!arg_directory)
                                return log_oom();
                }

                r = start_virtiofsd(
                                unit,
                                arg_directory,
                                /* source_uid= */ arg_uid_shift,
                                /* target_uid= */ 0,
                                /* uid_range= */ arg_uid_range,
                                runtime_dir,
                                sd_socket_activate,
                                &listen_address,
                                &child);
                if (r < 0)
                        return r;

                _cleanup_(sd_event_source_unrefp) sd_event_source *source = NULL;
                r = event_add_child_pidref(event, &source, &child, WEXITED, on_child_exit, /* userdata= */ NULL);
                if (r < 0)
                        return r;

                pidref_done(&child);
                children[n_children++] = TAKE_PTR(source);

                _cleanup_free_ char *escaped_listen_address = escape_qemu_value(listen_address);
                if (!escaped_listen_address)
                        return log_oom();

                if (strv_extend(&cmdline, "-chardev") < 0)
                        return log_oom();

                if (strv_extendf(&cmdline, "socket,id=rootdir,path=%s", escaped_listen_address) < 0)
                        return log_oom();

                if (strv_extend_many(
                                    &cmdline,
                                    "-device",
                                    "vhost-user-fs-pci,queue-size=1024,chardev=rootdir,tag=root") < 0)
                        return log_oom();

                if (strv_extend(&arg_kernel_cmdline_extra, "root=root rootfstype=virtiofs rw") < 0)
                        return log_oom();
        }

        size_t i = 0;
        FOREACH_ARRAY(drive, arg_extra_drives.drives, arg_extra_drives.n_drives) {
                if (strv_extend(&cmdline, "-blockdev") < 0)
                        return log_oom();

                _cleanup_free_ char *escaped_drive = escape_qemu_value(drive->path);
                if (!escaped_drive)
                        return log_oom();

                struct stat st;
                if (stat(drive->path, &st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", drive->path);

                const char *driver = NULL;
                if (S_ISREG(st.st_mode))
                        driver = "file";
                else if (S_ISBLK(st.st_mode)) {
                        if (drive->format == IMAGE_FORMAT_QCOW2)
                                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                                       "Block device '%s' cannot be used with 'qcow2' format, only 'raw' is supported.",
                                                       drive->path);
                        driver = "host_device";
                } else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected regular file or block device, not '%s'.", drive->path);

                if (strv_extendf(&cmdline, "driver=%s,cache.direct=off,cache.no-flush=on,file.driver=%s,file.filename=%s,node-name=vmspawn_extra_%zu", image_format_to_string(drive->format), driver, escaped_drive, i) < 0)
                        return log_oom();

                _cleanup_free_ char *drive_fn = NULL;
                r = path_extract_filename(drive->path, &drive_fn);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from path '%s': %m", drive->path);

                _cleanup_free_ char *escaped_drive_fn = escape_qemu_value(drive_fn);
                if (!escaped_drive_fn)
                        return log_oom();

                if (strv_extend(&cmdline, "-device") < 0)
                        return log_oom();

                if (strv_extendf(&cmdline, "virtio-blk-pci,drive=vmspawn_extra_%zu,serial=%s", i++, escaped_drive_fn) < 0)
                        return log_oom();
        }

        if (arg_console_mode != CONSOLE_GUI) {
                r = strv_prepend(&arg_kernel_cmdline_extra, "console=hvc0");
                if (r < 0)
                        return log_oom();
        }

        for (size_t j = 0; j < arg_runtime_mounts.n_mounts; j++) {
                RuntimeMount *m = arg_runtime_mounts.mounts + j;
                _cleanup_free_ char *listen_address = NULL;
                _cleanup_(fork_notify_terminate) PidRef child = PIDREF_NULL;

                if (!GREEDY_REALLOC(children, n_children + 1))
                        return log_oom();

                r = start_virtiofsd(
                                unit,
                                m->source,
                                /* source_uid= */ m->source_uid,
                                /* target_uid= */ m->target_uid,
                                /* uid_range= */ 1U,
                                runtime_dir,
                                sd_socket_activate,
                                &listen_address,
                                &child);
                if (r < 0)
                        return r;

                _cleanup_(sd_event_source_unrefp) sd_event_source *source = NULL;
                r = event_add_child_pidref(event, &source, &child, WEXITED, on_child_exit, /* userdata= */ NULL);
                if (r < 0)
                        return r;

                pidref_done(&child);
                children[n_children++] = TAKE_PTR(source);

                _cleanup_free_ char *escaped_listen_address = escape_qemu_value(listen_address);
                if (!escaped_listen_address)
                        return log_oom();

                if (strv_extend(&cmdline, "-chardev") < 0)
                        return log_oom();

                _cleanup_free_ char *id = NULL;
                if (asprintf(&id, "mnt%zu", j) < 0)
                        return log_oom();

                if (strv_extendf(&cmdline, "socket,id=%s,path=%s", id, escaped_listen_address) < 0)
                        return log_oom();

                if (strv_extend(&cmdline, "-device") < 0)
                        return log_oom();

                if (strv_extendf(&cmdline, "vhost-user-fs-pci,queue-size=1024,chardev=%1$s,tag=%1$s", id) < 0)
                        return log_oom();

                _cleanup_free_ char *clean_target = xescape(m->target, "\":");
                if (!clean_target)
                        return log_oom();

                if (strv_extendf(&arg_kernel_cmdline_extra, "systemd.mount-extra=\"%s:%s:virtiofs:%s\"",
                                 id, clean_target, m->read_only ? "ro" : "rw") < 0)
                        return log_oom();
        }

        _cleanup_(rm_rf_physical_and_freep) char *smbios_dir = NULL;
        r = mkdtemp_malloc("/var/tmp/vmspawn-smbios-XXXXXX", &smbios_dir);
        if (r < 0)
                return log_error_errno(r, "Failed to create temporary directory: %m");

        r = cmdline_add_kernel_cmdline(&cmdline, kernel, smbios_dir);
        if (r < 0)
                return r;

        r = cmdline_add_smbios11(&cmdline, smbios_dir);
        if (r < 0)
                return r;

        /* disable TPM autodetection if the user's hardware doesn't support it */
        if (!ARCHITECTURE_SUPPORTS_TPM) {
                if (arg_tpm > 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "TPM not supported on %s, refusing", architecture_to_string(native_architecture()));
                if (arg_tpm < 0) {
                        arg_tpm = false;
                        log_debug("TPM not support on %s, disabling tpm autodetection and continuing", architecture_to_string(native_architecture()));
                }
        }

        _cleanup_free_ char *swtpm = NULL;
        if (arg_tpm != 0) {
                if (arg_tpm_state_mode == TPM_STATE_AUTO && !arg_ephemeral) {
                        assert(!arg_tpm_state_path);

                        const char *p = ASSERT_PTR(arg_image ?: arg_directory);

                        _cleanup_free_ char *parent = NULL;
                        r = path_extract_directory(p, &parent);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract parent directory from '%s': %m", p);

                        _cleanup_free_ char *filename = NULL;
                        r = path_extract_filename(p, &filename);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract filename from '%s': %m", p);

                        if (!strextend(&filename, ".tpmstate"))
                                return log_oom();

                        arg_tpm_state_path = path_join(parent, filename);
                        if (!arg_tpm_state_path)
                                return log_oom();

                        log_debug("Storing TPM state persistently under '%s'.", arg_tpm_state_path);
                }

                r = find_executable("swtpm", &swtpm);
                if (r < 0) {
                        /* log if the user asked for swtpm and we cannot find it */
                        if (arg_tpm > 0)
                                return log_error_errno(r, "Failed to find swtpm binary: %m");
                        /* also log if we got an error other than ENOENT from find_executable */
                        if (r != -ENOENT && arg_tpm < 0)
                                return log_error_errno(r, "Error detecting swtpm: %m");
                }
        }

        _cleanup_free_ char *tpm_socket_address = NULL;
        if (swtpm) {
                _cleanup_(fork_notify_terminate) PidRef child = PIDREF_NULL;

                if (!GREEDY_REALLOC(children, n_children + 1))
                        return log_oom();

                r = start_tpm(unit, swtpm, runtime_dir, sd_socket_activate, &tpm_socket_address, &child);
                if (r < 0) {
                        /* only bail if the user asked for a tpm */
                        if (arg_tpm > 0)
                                return log_error_errno(r, "Failed to start tpm: %m");

                        log_debug_errno(r, "Failed to start tpm, ignoring: %m");
                }

                _cleanup_(sd_event_source_unrefp) sd_event_source *source = NULL;
                r = event_add_child_pidref(event, &source, &child, WEXITED, on_child_exit, /* userdata= */ NULL);
                if (r < 0)
                        return r;

                pidref_done(&child);
                children[n_children++] = TAKE_PTR(source);
        }

        if (tpm_socket_address) {
                _cleanup_free_ char *escaped_tpm_socket_address = escape_qemu_value(tpm_socket_address);
                if (!escaped_tpm_socket_address)
                        return log_oom();

                if (strv_extend(&cmdline, "-chardev") < 0)
                        return log_oom();

                if (strv_extend_joined(&cmdline, "socket,id=chrtpm,path=", tpm_socket_address) < 0)
                        return log_oom();

                if (strv_extend_many(&cmdline, "-tpmdev", "emulator,id=tpm0,chardev=chrtpm") < 0)
                        return log_oom();

                if (native_architecture() == ARCHITECTURE_X86_64)
                        r = strv_extend_many(&cmdline, "-device", "tpm-tis,tpmdev=tpm0");
                else if (IN_SET(native_architecture(), ARCHITECTURE_ARM64, ARCHITECTURE_ARM64_BE))
                        r = strv_extend_many(&cmdline, "-device", "tpm-tis-device,tpmdev=tpm0");
                if (r < 0)
                        return log_oom();
        }

        char *initrd = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *merged_initrd = NULL;
        size_t n_initrds = strv_length(arg_initrds);

        if (n_initrds == 1)
                initrd = arg_initrds[0];
        else if (n_initrds > 1) {
                r = merge_initrds(&merged_initrd);
                if (r < 0)
                        return r;

                initrd = merged_initrd;
        }

        if (initrd) {
                r = strv_extend_many(&cmdline, "-initrd", initrd);
                if (r < 0)
                        return log_oom();
        }

        if (arg_forward_journal) {
                _cleanup_free_ char *listen_address = NULL;

                if (!GREEDY_REALLOC(children, n_children + 1))
                        return log_oom();

                _cleanup_(fork_notify_terminate) PidRef child = PIDREF_NULL;
                r = start_systemd_journal_remote(unit, child_cid, sd_socket_activate, &listen_address, &child);
                if (r < 0)
                        return r;

                _cleanup_(sd_event_source_unrefp) sd_event_source *source = NULL;
                r = event_add_child_pidref(event, &source, &child, WEXITED, on_child_exit, /* userdata= */ NULL);
                if (r < 0)
                        return r;

                pidref_done(&child);
                children[n_children++] = TAKE_PTR(source);

                r = machine_credential_add(&arg_credentials, "journal.forward_to_socket", listen_address, SIZE_MAX);
                if (r < 0)
                        return r;
        }

        if (arg_pass_ssh_key) {
                _cleanup_free_ char *scope_prefix = NULL, *privkey_path = NULL, *pubkey_path = NULL;
                const char *key_type = arg_ssh_key_type ?: "ed25519";

                r = unit_name_to_prefix(unit, &scope_prefix);
                if (r < 0)
                        return log_error_errno(r, "Failed to strip .scope suffix from scope: %m");

                privkey_path = strjoin(runtime_dir, "/", scope_prefix, "-", key_type);
                if (!privkey_path)
                        return log_oom();

                pubkey_path = strjoin(privkey_path, ".pub");
                if (!pubkey_path)
                        return log_oom();

                r = generate_ssh_keypair(privkey_path, key_type);
                if (r < 0)
                        return r;

                ssh_private_key_path = TAKE_PTR(privkey_path);
                ssh_public_key_path = TAKE_PTR(pubkey_path);
        }

        if (ssh_public_key_path && ssh_private_key_path) {
                _cleanup_free_ char *scope_prefix = NULL, *cred_path = NULL;

                cred_path = strjoin("ssh.ephemeral-authorized_keys-all:", ssh_public_key_path);
                if (!cred_path)
                        return log_oom();

                r = machine_credential_load(&arg_credentials, cred_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to load credential %s: %m", cred_path);

                r = unit_name_to_prefix(unit, &scope_prefix);
                if (r < 0)
                        return log_error_errno(r, "Failed to strip .scope suffix from scope: %m");

                /* on distros that provide their own sshd@.service file we need to provide a dropin which
                 * picks up our public key credential */
                r = machine_credential_add(
                                &arg_credentials,
                                "systemd.unit-dropin.sshd-vsock@.service",
                                "[Service]\n"
                                "ExecStart=\n"
                                "ExecStart=-sshd -i -o 'AuthorizedKeysFile=%d/ssh.ephemeral-authorized_keys-all .ssh/authorized_keys'\n"
                                "ImportCredential=ssh.ephemeral-authorized_keys-all\n",
                                SIZE_MAX);
                if (r < 0)
                        return log_error_errno(r, "Failed to set credential systemd.unit-dropin.sshd-vsock@.service: %m");
        }

        if (ARCHITECTURE_SUPPORTS_SMBIOS)
                FOREACH_ARRAY(cred, arg_credentials.credentials, arg_credentials.n_credentials) {
                        _cleanup_free_ char *p = NULL, *cred_data_b64 = NULL;
                        ssize_t n;

                        n = base64mem(cred->data, cred->size, &cred_data_b64);
                        if (n < 0)
                                return log_oom();

                        p = path_join(smbios_dir, cred->id);
                        if (!p)
                                return log_oom();

                        r = write_string_filef(
                                        p,
                                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE|WRITE_STRING_FILE_MODE_0600,
                                        "io.systemd.credential.binary:%s=%s", cred->id, cred_data_b64);
                        if (r < 0)
                                return log_error_errno(r, "Failed to write smbios credential file %s: %m", p);

                        r = strv_extend(&cmdline, "-smbios");
                        if (r < 0)
                                return log_oom();

                        r = strv_extend_joined(&cmdline, "type=11,path=", p);
                        if (r < 0)
                                return log_oom();
                }

        if (use_vsock) {
                notify_sock_fd = open_vsock();
                if (notify_sock_fd < 0)
                        return log_error_errno(notify_sock_fd, "Failed to open VSOCK: %m");

                r = cmdline_add_vsock(&cmdline, notify_sock_fd);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_error_errno(r, "Failed to call getsockname on VSOCK: %m");
        }

        const char *e = secure_getenv("SYSTEMD_VMSPAWN_QEMU_EXTRA");
        if (e) {
                r = strv_split_and_extend_full(&cmdline, e,
                                               /* separators= */ NULL, /* filter_duplicates= */ false,
                                               EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse $SYSTEMD_VMSPAWN_QEMU_EXTRA: %m");
        }

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *joined = quote_command_line(cmdline, SHELL_ESCAPE_EMPTY);
                if (!joined)
                        return log_oom();

                log_debug("Executing: %s", joined);
        }

        _cleanup_(pidref_done) PidRef child_pidref = PIDREF_NULL;
        r = pidref_safe_fork_full(
                        qemu_binary,
                        /* stdio_fds= */ NULL,
                        pass_fds, n_pass_fds,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_CLOEXEC_OFF|FORK_RLIMIT_NOFILE_SAFE,
                        &child_pidref);
        if (r < 0)
                return r;
        if (r == 0) {
                if (setenv("LANG", "C.UTF-8", 0) < 0) {
                        log_oom();
                        goto fail;
                }

                execv(qemu_binary, cmdline);
                log_error_errno(errno, "Failed to execve %s: %m", qemu_binary);
        fail:
                _exit(EXIT_FAILURE);
        }

        /* Close relevant fds we passed to qemu in the parent. We don't need them anymore. */
        child_vsock_fd = safe_close(child_vsock_fd);
        tap_fd = safe_close(tap_fd);

        if (!arg_keep_unit) {
                /* When a new scope is created for this container, then we'll be registered as its controller, in which
                 * case PID 1 will send us a friendly RequestStop signal, when it is asked to terminate the
                 * scope. Let's hook into that, and cleanly shut down the container, and print a friendly message. */

                r = sd_bus_match_signal_async(
                                runtime_bus,
                                /* ret= */ NULL,
                                "org.freedesktop.systemd1",
                                /* path= */ NULL,
                                "org.freedesktop.systemd1.Scope",
                                "RequestStop",
                                on_request_stop,
                                /* install_callback= */ NULL,
                                /* userdata= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to request RequestStop match: %m");
        }

        bool scope_allocated = false;
        if (!arg_keep_unit && (!arg_register || arg_runtime_scope != RUNTIME_SCOPE_SYSTEM)) {
                r = allocate_scope(
                                runtime_bus,
                                arg_machine,
                                &child_pidref,
                                children,
                                n_children,
                                unit,
                                arg_slice,
                                arg_property,
                                /* allow_pidfd= */ true);
                if (r < 0)
                        return r;

                scope_allocated = true;
        } else {
                if (arg_runtime_scope == RUNTIME_SCOPE_SYSTEM)
                        r = cg_pid_get_unit(0, &unit);
                else
                        r = cg_pid_get_user_unit(0, &unit);
                if (r < 0)
                        return log_error_errno(r, "Failed to get our own unit: %m");
        }

        bool registered_system = false, registered_runtime = false;
        if (arg_register) {
                char vm_address[STRLEN("vsock/") + DECIMAL_STR_MAX(unsigned)];
                xsprintf(vm_address, "vsock/%u", child_cid);
                r = register_machine(
                                system_bus,
                                arg_machine,
                                arg_uuid,
                                "systemd-vmspawn",
                                &child_pidref,
                                arg_directory,
                                child_cid,
                                child_cid != VMADDR_CID_ANY ? vm_address : NULL,
                                ssh_private_key_path,
                                !arg_keep_unit && arg_runtime_scope == RUNTIME_SCOPE_SYSTEM,
                                RUNTIME_SCOPE_SYSTEM);
                if (r < 0) {
                        /* if privileged the request to register definitely failed */
                        if (arg_runtime_scope == RUNTIME_SCOPE_SYSTEM)
                                return r;

                        log_notice_errno(r, "Failed to register machine in system context, will try in user context.");
                } else
                        registered_system = true;

                if (arg_runtime_scope == RUNTIME_SCOPE_USER) {
                        r = register_machine(
                                        runtime_bus,
                                        arg_machine,
                                        arg_uuid,
                                        "systemd-vmspawn",
                                        &child_pidref,
                                        arg_directory,
                                        child_cid,
                                        child_cid != VMADDR_CID_ANY ? vm_address : NULL,
                                        ssh_private_key_path,
                                        !arg_keep_unit,
                                        RUNTIME_SCOPE_USER);
                        if (r < 0) {
                                if (!registered_system) /* neither registration worked: fail */
                                        return r;

                                log_notice_errno(r, "Failed to register machine in user context, but succeeded in system context, will proceed.");
                        } else
                                registered_runtime = true;
                }
        }

        /* Report that the VM is now set up */
        (void) sd_notifyf(/* unset_environment= */ false,
                          "STATUS=VM started.\n"
                          "X_VMSPAWN_LEADER_PID=" PID_FMT, child_pidref.pid);
        if (!arg_notify_ready) {
                r = sd_notify(/* unset_environment= */ false, "READY=1\n");
                if (r < 0)
                        log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");
        }

        /* All operations that might need Polkit authorizations (i.e. machine registration, netif
         * acquisition, …) are complete now, get rid of the agent again, so that we retain exclusive control
         * of the TTY from now on. */
        polkit_agent_close();

        _cleanup_(sd_event_source_unrefp) sd_event_source *notify_event_source = NULL;

        if (system_bus) {
                r = sd_bus_attach_event(system_bus, event, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach system bus to event loop: %m");
        }

        if (user_bus) {
                r = sd_bus_attach_event(user_bus, event, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach user bus to event loop: %m");
        }

        int exit_status = INT_MAX;
        if (use_vsock) {
                r = setup_notify_parent(event, notify_sock_fd, &exit_status, &notify_event_source);
                if (r < 0)
                        return log_error_errno(r, "Failed to setup event loop to handle VSOCK notify events: %m");
        }

        /* Used when talking to pid1 via SSH, but must survive until the function ends. */
        SSHInfo ssh_info = {
                .cid = child_cid,
                .private_key_path = ssh_private_key_path,
                .port = 22,
        };
        ShutdownInfo shutdown_info = {
                .ssh_info = &ssh_info,
                .pidref = &child_pidref,
        };

        (void) sd_event_add_signal(event, NULL, SIGINT | SD_EVENT_SIGNAL_PROCMASK, shutdown_vm_graceful, &shutdown_info);
        (void) sd_event_add_signal(event, NULL, SIGTERM | SD_EVENT_SIGNAL_PROCMASK, shutdown_vm_graceful, &shutdown_info);
        (void) sd_event_add_signal(event, NULL, (SIGRTMIN+4) | SD_EVENT_SIGNAL_PROCMASK, shutdown_vm_graceful, &shutdown_info);

        (void) sd_event_add_signal(event, NULL, (SIGRTMIN+18) | SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, NULL);

        r = sd_event_add_memory_pressure(event, NULL, NULL, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to allocate memory pressure event source, ignoring: %m");

        /* Exit when the child exits */
        r = event_add_child_pidref(event, /* ret= */ NULL, &child_pidref, WEXITED, on_child_exit, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to watch qemu process: %m");

        _cleanup_(osc_context_closep) sd_id128_t osc_context_id = SD_ID128_NULL;
        _cleanup_(pty_forward_freep) PTYForward *forward = NULL;
        if (master >= 0) {
                if (!terminal_is_dumb()) {
                        r = osc_context_open_vm(arg_machine, /* ret_seq= */ NULL, &osc_context_id);
                        if (r < 0)
                                return r;
                }

                r = pty_forward_new(event, master, ptyfwd_flags, &forward);
                if (r < 0)
                        return log_error_errno(r, "Failed to create PTY forwarder: %m");

                if (!arg_background) {
                        _cleanup_free_ char *bg = NULL;

                        r = terminal_tint_color(130 /* green */, &bg);
                        if (r < 0)
                                log_debug_errno(r, "Failed to determine terminal background color, not tinting.");
                        else
                                (void) pty_forward_set_background_color(forward, bg);
                } else if (!isempty(arg_background))
                        (void) pty_forward_set_background_color(forward, arg_background);

                (void) pty_forward_set_window_title(forward, GLYPH_GREEN_CIRCLE, /* hostname= */ NULL,
                                                    STRV_MAKE("Virtual Machine", arg_machine));
        }

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        /* Kill if it is not dead yet anyway */
        if (scope_allocated)
                terminate_scope(runtime_bus, arg_machine);

        if (registered_system)
                (void) unregister_machine(system_bus, arg_machine);
        if (registered_runtime)
                (void) unregister_machine(runtime_bus, arg_machine);

        if (use_vsock) {
                if (exit_status == INT_MAX) {
                        log_debug("Couldn't retrieve inner EXIT_STATUS from VSOCK");
                        return EXIT_SUCCESS;
                }
                if (exit_status != 0)
                        log_warning("Non-zero exit code received: %d", exit_status);
                return exit_status;
        }

        return 0;
}

static int determine_names(void) {
        int r;

        if (!arg_directory && !arg_image) {
                if (arg_machine) {
                        _cleanup_(image_unrefp) Image *i = NULL;

                        /* Use both user and system images in user mode, use only system images in system mode. */
                        r = image_find(arg_runtime_scope == RUNTIME_SCOPE_USER ? _RUNTIME_SCOPE_INVALID : arg_runtime_scope,
                                       IMAGE_MACHINE,
                                       arg_machine,
                                       /* root= */ NULL,
                                       &i);
                        if (r == -ENOENT)
                                return log_error_errno(r, "No image for machine '%s'.", arg_machine);
                        if (r < 0)
                                return log_error_errno(r, "Failed to find image for machine '%s': %m", arg_machine);

                        if (IN_SET(i->type, IMAGE_RAW, IMAGE_BLOCK))
                                r = free_and_strdup(&arg_image, i->path);
                        else if (IN_SET(i->type, IMAGE_DIRECTORY, IMAGE_SUBVOLUME))
                                r = free_and_strdup(&arg_directory, i->path);
                        else
                                assert_not_reached();
                        if (r < 0)
                                return log_oom();
                } else {
                        r = safe_getcwd(&arg_directory);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine current directory: %m");
                }
        }

        if (!arg_machine) {
                if (arg_directory && path_equal(arg_directory, "/")) {
                        arg_machine = gethostname_malloc();
                        if (!arg_machine)
                                return log_oom();
                } else if (arg_image) {
                        char *e;

                        r = path_extract_filename(arg_image, &arg_machine);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract file name from '%s': %m", arg_image);

                        /* Truncate suffix if there is one */
                        e = endswith(arg_machine, ".raw");
                        if (e)
                                *e = 0;
                } else {
                        r = path_extract_filename(arg_directory, &arg_machine);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract file name from '%s': %m", arg_directory);
                }
                /* Add a random suffix when this is an ephemeral machine, so that we can run many
                 * instances at once without manually having to specify -M each time. */
                if (arg_ephemeral)
                        if (strextendf(&arg_machine, "-%016" PRIx64, random_u64()) < 0)
                                return log_oom();

                hostname_cleanup(arg_machine);
                if (!hostname_is_valid(arg_machine, 0))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine machine name automatically, please use -M.");
        }

        return 0;
}

static int verify_arguments(void) {
        if (!strv_isempty(arg_initrds) && !arg_linux)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --initrd= cannot be used without --linux=.");

        return 0;
}

static int run(int argc, char *argv[]) {
        int r, kvm_device_fd = -EBADF, vhost_device_fd = -EBADF;
        _cleanup_strv_free_ char **names = NULL;

        log_setup();

        arg_runtime_scope = getuid() == 0 ? RUNTIME_SCOPE_SYSTEM : RUNTIME_SCOPE_USER;

        r = parse_environment();
        if (r < 0)
                return r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = determine_names();
        if (r < 0)
                return r;

        r = verify_arguments();
        if (r < 0)
                return r;

        if (!arg_quiet && arg_console_mode != CONSOLE_GUI) {
                _cleanup_free_ char *u = NULL;
                const char *vm_path = arg_image ?: arg_directory;
                (void) terminal_urlify_path(vm_path, vm_path, &u);

                log_info("%s %sSpawning VM %s on %s.%s",
                         glyph(GLYPH_LIGHT_SHADE), ansi_grey(), arg_machine, u ?: vm_path, ansi_normal());

                if (arg_console_mode == CONSOLE_INTERACTIVE)
                        log_info("%s %sPress %sCtrl-]%s three times within 1s to kill VM.%s",
                                 glyph(GLYPH_LIGHT_SHADE), ansi_grey(), ansi_highlight(), ansi_grey(), ansi_normal());
                else if (arg_console_mode == CONSOLE_NATIVE)
                        log_info("%s %sPress %sCtrl-a x%s to kill VM.%s",
                                 glyph(GLYPH_LIGHT_SHADE), ansi_grey(), ansi_highlight(), ansi_grey(), ansi_normal());
        }

        int n = sd_listen_fds_with_names(true, &names);
        if (n < 0)
                return log_error_errno(n, "Failed to get passed file descriptors: %m");

        for (int i = 0; i < n; i++) {
                int fd = SD_LISTEN_FDS_START + i;
                if (streq(names[i], "kvm"))
                        kvm_device_fd = fd;
                else if (streq(names[i], "vhost-vsock"))
                        vhost_device_fd = fd;
                else {
                        log_notice("Couldn't recognize passed fd %d (%s), closing fd and ignoring...", fd, names[i]);
                        safe_close(fd);
                }
        }

        return run_virtual_machine(kvm_device_fd, vhost_device_fd);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
