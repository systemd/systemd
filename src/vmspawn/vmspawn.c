/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
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
#include "build-path.h"
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
#include "fileio.h"
#include "fork-notify.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "gpt.h"
#include "group-record.h"
#include "hexdecoct.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "kernel-image.h"
#include "log.h"
#include "machine-bind-user.h"
#include "machine-credential.h"
#include "machine-register.h"
#include "main-func.h"
#include "memfd-util.h"
#include "mkdir.h"
#include "namespace-util.h"
#include "netif-util.h"
#include "nsresource.h"
#include "osc-context.h"
#include "options.h"
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
#include "set.h"
#include "sha256.h"
#include "signal-util.h"
#include "snapshot-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "swtpm-util.h"
#include "sync-util.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "uid-classification.h"
#include "unit-name.h"
#include "user-record.h"
#include "user-util.h"
#include "utf8.h"
#include "vmspawn-bind-volume.h"
#include "vmspawn-mount.h"
#include "vmspawn-qemu-config.h"
#include "vmspawn-qmp.h"
#include "vmspawn-scope.h"
#include "vmspawn-settings.h"
#include "vmspawn-util.h"
#include "vmspawn-varlink.h"

#define VM_TAP_HASH_KEY SD_ID128_MAKE(01,d0,c6,4c,2b,df,24,fb,c0,f8,b2,09,7d,59,b2,93)

#define DISK_SERIAL_MAX_LEN_SCSI        30
#define DISK_SERIAL_MAX_LEN_NVME        20
#define DISK_SERIAL_MAX_LEN_VIRTIO_BLK  20

/* First and one-past-last pcie.0 device-numbers used for multifunction-packed
 * pcie-root-ports. Sits above the auto-assigned virtio devices (0x01-0x03) and
 * below 0x1f, which q35 reserves for ICH9 LPC at 0x1f.0 (single-function). */
#define VMSPAWN_PCIE_PACK_BASE_SLOT 0x10
#define VMSPAWN_PCIE_PACK_END_SLOT  0x1f
#define VMSPAWN_PCIE_PACK_MAX_PORTS ((VMSPAWN_PCIE_PACK_END_SLOT - VMSPAWN_PCIE_PACK_BASE_SLOT) * 8)

/* An enum controlling how auxiliary state for the VM are maintained, i.e. the TPM state and the EFI variable
 * NVRAM. */
typedef enum StateMode {
        STATE_OFF,      /* keep no state around */
        STATE_AUTO,     /* keep state around if not ephemeral, derive path from image/directory */
        STATE_PATH,     /* explicitly specified location */
        _STATE_MODE_MAX,
        _STATE_MODE_INVALID = -EINVAL,
} StateMode;

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
static uint64_t arg_ram_max = 0;
static unsigned arg_ram_slots = 0;
static int arg_kvm = -1;
static int arg_vsock = -1;
static unsigned arg_vsock_cid = VMADDR_CID_ANY;
static int arg_tpm = -1;
static char *arg_linux = NULL;
static KernelImageType arg_linux_image_type = _KERNEL_IMAGE_TYPE_INVALID;
static char **arg_initrds = NULL;
static ConsoleMode arg_console_mode = CONSOLE_INTERACTIVE;
static ConsoleTransport arg_console_transport = CONSOLE_TRANSPORT_VIRTIO;
static NetworkStack arg_network_stack = NETWORK_STACK_NONE;
static MachineCredentialContext arg_credentials = {};
static uid_t arg_uid_shift = UID_INVALID, arg_uid_range = 0x10000U;
static RuntimeMountContext arg_runtime_mounts = {};
static char *arg_firmware = NULL;
static Firmware arg_firmware_type = _FIRMWARE_INVALID;
static bool arg_firmware_describe = false;
static Set *arg_firmware_features_include = NULL;
static Set *arg_firmware_features_exclude = NULL;
static char *arg_forward_journal = NULL;
static uint64_t arg_forward_journal_max_use = UINT64_MAX;
static uint64_t arg_forward_journal_keep_free = UINT64_MAX;
static uint64_t arg_forward_journal_max_file_size = UINT64_MAX;
static uint64_t arg_forward_journal_max_files = UINT64_MAX;
static int arg_register = -1;
static bool arg_keep_unit = false;
static sd_id128_t arg_uuid = {};
static char **arg_kernel_cmdline_extra = NULL;
static ExtraDriveContext arg_extra_drives = {};
static BindVolumes arg_bind_volumes = {};
static char *arg_background = NULL;
static bool arg_pass_ssh_key = true;
static char *arg_ssh_key_type = NULL;
static bool arg_discard_disk = true;
static DiskType arg_image_disk_type = DISK_TYPE_VIRTIO_BLK;
static struct ether_addr arg_network_provided_mac = {};
static char **arg_smbios11 = NULL;
static uint64_t arg_grow_image = 0;
static char *arg_tpm_state_path = NULL;
static StateMode arg_tpm_state_mode = STATE_AUTO;
static char *arg_efi_nvram_template = NULL;
static char *arg_efi_nvram_state_path = NULL;
static StateMode arg_efi_nvram_state_mode = STATE_AUTO;
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
STATIC_DESTRUCTOR_REGISTER(arg_firmware_features_include, set_freep);
STATIC_DESTRUCTOR_REGISTER(arg_firmware_features_exclude, set_freep);
STATIC_DESTRUCTOR_REGISTER(arg_linux, freep);
STATIC_DESTRUCTOR_REGISTER(arg_initrds, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_runtime_mounts, runtime_mount_context_done);
STATIC_DESTRUCTOR_REGISTER(arg_forward_journal, freep);
STATIC_DESTRUCTOR_REGISTER(arg_kernel_cmdline_extra, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_extra_drives, extra_drive_context_done);
STATIC_DESTRUCTOR_REGISTER(arg_bind_volumes, bind_volumes_done);
STATIC_DESTRUCTOR_REGISTER(arg_background, freep);
STATIC_DESTRUCTOR_REGISTER(arg_ssh_key_type, freep);
STATIC_DESTRUCTOR_REGISTER(arg_smbios11, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm_state_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_efi_nvram_template, freep);
STATIC_DESTRUCTOR_REGISTER(arg_efi_nvram_state_path, freep);
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

        static const char* const groups[] = {
                NULL,
                "Image",
                "Host Configuration",
                "Execution",
                "System Identity",
                "Properties",
                "User Namespacing",
                "Mounts",
                "Integration",
                "Input/Output",
                "Credentials",
        };

        Table* tables[ELEMENTSOF(groups)] = {};
        CLEANUP_ELEMENTS(tables, table_unref_array_clear);

        for (size_t i = 0; i < ELEMENTSOF(groups); i++) {
                r = option_parser_get_help_table_group(groups[i], &tables[i]);
                if (r < 0)
                        return r;
        }

        (void) table_sync_column_widths(0, tables[0], tables[1], tables[2], tables[3], tables[4],
                                        tables[5], tables[6], tables[7], tables[8], tables[9], tables[10]);

        printf("%s [OPTIONS...] [ARGUMENTS...]\n\n"
               "%sSpawn a command or OS in a virtual machine.%s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());

        for (size_t i = 0; i < ELEMENTSOF(groups); i++) {
                printf("\n%s%s:%s\n", ansi_underline(), groups[i] ?: "Options", ansi_normal());

                r = table_print_or_warn(tables[i]);
                if (r < 0)
                        return r;
        }

        printf("\nSee the %s for details.\n", link);
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

static int parse_ram(const char *s) {
        _cleanup_free_ char *ram = NULL, *ram_max = NULL, *ram_slots = NULL;
        int r;

        assert(s);

        const char *p = s;
        r = extract_many_words(&p, ":", EXTRACT_DONT_COALESCE_SEPARATORS, &ram, &ram_max, &ram_slots);
        if (r < 0)
                return log_error_errno(r, "Failed to parse --ram=%s: %m", s);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to parse --ram=%s", s);
        if (!isempty(p))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected trailing data in --ram=%s", s);

        r = parse_size(ram, 1024, &arg_ram);
        if (r < 0)
                return log_error_errno(r, "Failed to parse --ram=%s: %m", s);

        if (!isempty(ram_max)) {
                r = parse_size(ram_max, 1024, &arg_ram_max);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse --ram=%s: %m", s);
        } else
                arg_ram_max = 0;

        if (!isempty(ram_slots)) {
                r = safe_atou(ram_slots, &arg_ram_slots);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse --ram=%s: %m", s);
        } else
                arg_ram_slots = 0;

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        /* Firmware with enrolled keys has been known to cause issues, skip by default */
        r = set_put_strdup(&arg_firmware_features_exclude, "enrolled-keys");
        if (r < 0)
                return log_oom();

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv, OPTION_PARSER_STOP_AT_FIRST_NONOPTION };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION('q', "quiet", NULL, "Do not show status information"):
                        arg_quiet = true;
                        break;

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                OPTION_LONG("system", NULL, "Run in the system service manager scope"):
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                OPTION_LONG("user", NULL, "Run in the user service manager scope"):
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                OPTION_GROUP("Image"): {}

                OPTION('D', "directory", "PATH", "Root directory for the VM"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_directory);
                        if (r < 0)
                                return r;
                        break;

                OPTION('x', "ephemeral", NULL, "Run VM with snapshot of the disk or directory"):
                        arg_ephemeral = true;
                        break;

                OPTION('i', "image", "FILE|DEVICE", "Root file system disk image or device for the VM"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image-format", "FORMAT", "Specify disk image format (raw, qcow2; default: raw)"):
                        arg_image_format = image_format_from_string(opts.arg);
                        if (arg_image_format < 0)
                                return log_error_errno(arg_image_format,
                                                       "Invalid image format: %s", opts.arg);
                        break;

                OPTION_LONG("image-disk-type", "TYPE",
                            "Specify disk type (virtio-blk, virtio-scsi, nvme, scsi-cd; default: virtio-blk)"):
                        arg_image_disk_type = disk_type_from_string(opts.arg);
                        if (arg_image_disk_type < 0)
                                return log_error_errno(arg_image_disk_type,
                                                       "Invalid image disk type: %s", opts.arg);
                        break;

                OPTION_GROUP("Host Configuration"): {}

                OPTION_LONG("cpus", "CPUS", "Configure number of CPUs in guest"): {}
                OPTION_LONG("qemu-smp", "CPUS", /* help= */ NULL):  /* Compat alias */
                        r = free_and_strdup_warn(&arg_cpus, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("ram", "BYTES[:MAXBYTES[:SLOTS]]",
                            "Configure guest's RAM size (and max/slots for hotplug)"): {}
                OPTION_LONG("qemu-mem", "BYTES", /* help= */ NULL):  /* Compat alias */
                        r = parse_ram(opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("kvm", "BOOL", "Enable use of KVM"): {}
                OPTION_LONG("qemu-kvm", "BOOL", /* help= */ NULL):  /* Compat alias */
                        r = parse_tristate_argument_with_auto("--kvm=", opts.arg, &arg_kvm);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("vsock", "BOOL", "Override autodetection of VSOCK support"): {}
                OPTION_LONG("qemu-vsock", "BOOL", /* help= */ NULL):  /* Compat alias */
                        r = parse_tristate_argument_with_auto("--vsock=", opts.arg, &arg_vsock);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("vsock-cid", "CID", "Specify the CID to use for the guest's VSOCK support"):
                        if (isempty(opts.arg))
                                arg_vsock_cid = VMADDR_CID_ANY;
                        else {
                                unsigned cid;

                                r = vsock_parse_cid(opts.arg, &cid);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse --vsock-cid: %s", opts.arg);
                                if (!VSOCK_CID_IS_REGULAR(cid))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Specified CID is not regular, refusing: %u", cid);

                                arg_vsock_cid = cid;
                        }
                        break;

                OPTION_LONG("tpm", "BOOL", "Enable use of a virtual TPM"):
                        r = parse_tristate_argument_with_auto("--tpm=", opts.arg, &arg_tpm);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("tpm-state", "off|auto|PATH", "Where to store TPM state"):
                        r = isempty(opts.arg) ? false :
                                streq(opts.arg, "auto") ? true :
                                parse_boolean(opts.arg);
                        if (r >= 0) {
                                arg_tpm_state_mode = r ? STATE_AUTO : STATE_OFF;
                                arg_tpm_state_path = mfree(arg_tpm_state_path);
                                break;
                        }

                        if (!path_is_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid path in --tpm-state= parameter: %s", opts.arg);

                        if (!path_is_absolute(opts.arg) && !startswith(opts.arg, "./"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Path in --tpm-state= parameter must be absolute or start with './': %s", opts.arg);

                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_tpm_state_path);
                        if (r < 0)
                                return r;

                        arg_tpm_state_mode = STATE_PATH;
                        break;

                OPTION_LONG("efi-nvram-template", "PATH", "Set the path to the EFI NVRAM template file to use"):
                        if (!isempty(opts.arg) && !path_is_absolute(opts.arg) && !startswith(opts.arg, "./"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Absolute path or path starting with './' required.");

                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_efi_nvram_template);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("efi-nvram-state", "off|auto|PATH", "Where to store EFI Variable NVRAM state"):
                        r = isempty(opts.arg) ? false :
                                streq(opts.arg, "auto") ? true :
                                parse_boolean(opts.arg);
                        if (r >= 0) {
                                arg_efi_nvram_state_mode = r ? STATE_AUTO : STATE_OFF;
                                arg_efi_nvram_state_path = mfree(arg_efi_nvram_state_path);
                                break;
                        }

                        if (!path_is_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid path in --efi-nvram-state= parameter: %s", opts.arg);

                        if (!path_is_absolute(opts.arg) && !startswith(opts.arg, "./"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Path in --efi-nvram-state= parameter must be absolute or start with './': %s", opts.arg);

                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_efi_nvram_state_path);
                        if (r < 0)
                                return r;

                        arg_efi_nvram_state_mode = STATE_PATH;
                        break;

                OPTION_LONG("linux", "PATH", "Specify the linux kernel for direct kernel boot"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_linux);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("initrd", "PATH", "Specify the initrd for direct kernel boot"): {
                        _cleanup_free_ char *initrd_path = NULL;
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &initrd_path);
                        if (r < 0)
                                return r;

                        r = strv_consume(&arg_initrds, TAKE_PTR(initrd_path));
                        if (r < 0)
                                return log_oom();
                        break;
                }

                OPTION('n', "network-tap", NULL, "Create a TAP device for networking"):
                        arg_network_stack = NETWORK_STACK_TAP;
                        break;

                OPTION_LONG("network-user-mode", NULL, "Use user mode networking"):
                        arg_network_stack = NETWORK_STACK_USER;
                        break;

                OPTION_LONG("secure-boot", "BOOL|auto", "Enable searching for firmware supporting SecureBoot"): {
                        int b;

                        r = parse_tristate_argument_with_auto("--secure-boot=", opts.arg, &b);
                        if (r < 0)
                                return r;

                        free(set_remove(arg_firmware_features_include, "secure-boot"));
                        free(set_remove(arg_firmware_features_exclude, "secure-boot"));

                        if (b >= 0) {
                                r = set_put_strdup(b > 0 ? &arg_firmware_features_include : &arg_firmware_features_exclude, "secure-boot");
                                if (r < 0)
                                        return log_oom();
                        }
                        break;
                }

                OPTION_LONG("firmware", "auto|uefi|bios|none|PATH|list|describe",
                            "Select firmware to use, or a firmware definition file (or list/describe available)"): {
                        if (isempty(opts.arg) || streq(opts.arg, "auto")) {
                                arg_firmware = mfree(arg_firmware);
                                arg_firmware_type = _FIRMWARE_INVALID;
                                arg_firmware_describe = false;
                                break;
                        }

                        if (streq(opts.arg, "list")) {
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

                        if (streq(opts.arg, "describe")) {
                                /* Handled after argument parsing so that --firmware-features= is
                                 * taken into account. */
                                arg_firmware = mfree(arg_firmware);
                                /* We only look for UEFI firmware when "describe" is specified. */
                                arg_firmware_type = FIRMWARE_UEFI;
                                arg_firmware_describe = true;
                                break;
                        }

                        Firmware f = firmware_from_string(opts.arg);
                        if (f >= 0) {
                                arg_firmware = mfree(arg_firmware);
                                arg_firmware_type = f;
                                arg_firmware_describe = false;
                                break;
                        }

                        if (!path_is_absolute(opts.arg) && !startswith(opts.arg, "./"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Expected one of 'auto', 'uefi', 'bios', 'none', 'list', 'describe', or an absolute path or path starting with './', got: %s",
                                                       opts.arg);

                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_firmware);
                        if (r < 0)
                                return r;

                        arg_firmware_type = FIRMWARE_UEFI;
                        arg_firmware_describe = false;
                        break;
                }

                OPTION_LONG("firmware-features", "FEATURE,...|list",
                            "Require/exclude specific firmware features"): {
                        if (isempty(opts.arg)) {
                                arg_firmware_features_include = set_free(arg_firmware_features_include);
                                arg_firmware_features_exclude = set_free(arg_firmware_features_exclude);
                                break;
                        }

                        if (streq(opts.arg, "list")) {
                                _cleanup_strv_free_ char **l = NULL;

                                r = list_ovmf_firmware_features(&l);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to list firmware features: %m");

                                bool nl = false;
                                fputstrv(stdout, l, "\n", &nl);
                                if (nl)
                                        putchar('\n');

                                return 0;
                        }

                        _cleanup_strv_free_ char **features = strv_split(opts.arg, ",");
                        if (!features)
                                return log_oom();

                        STRV_FOREACH(feature, features) {
                                const char *e = startswith(*feature, "~");
                                r = set_put_strdup(e ? &arg_firmware_features_exclude : &arg_firmware_features_include, e ?: *feature);
                                if (r < 0)
                                        return log_oom();
                        }
                        break;
                }

                OPTION_LONG("discard-disk", "BOOL", "Control processing of discard requests"):
                        r = parse_boolean_argument("--discard-disk=", opts.arg, &arg_discard_disk);
                        if (r < 0)
                                return r;
                        break;

                OPTION('G', "grow-image", "BYTES", "Grow image file to specified size in bytes"):
                        if (isempty(opts.arg)) {
                                arg_grow_image = 0;
                                break;
                        }

                        r = parse_size(opts.arg, 1024, &arg_grow_image);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --grow-image= parameter: %s", opts.arg);
                        break;

                OPTION_GROUP("Execution"): {}

                OPTION('s', "smbios11", "STRING", "Pass an arbitrary SMBIOS Type #11 string to the VM"):
                        if (isempty(opts.arg)) {
                                arg_smbios11 = strv_free(arg_smbios11);
                                break;
                        }

                        if (!utf8_is_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "SMBIOS Type 11 string is not UTF-8 clean, refusing: %s", opts.arg);

                        if (strv_extend(&arg_smbios11, opts.arg) < 0)
                                return log_oom();
                        break;

                OPTION_LONG("notify-ready", "BOOL", "Wait for ready notification from the VM"):
                        r = parse_boolean_argument("--notify-ready=", opts.arg, &arg_notify_ready);
                        if (r < 0)
                                return r;
                        break;

                OPTION_GROUP("System Identity"): {}

                OPTION('M', "machine", "NAME", "Set the machine name for the VM"):
                        if (isempty(opts.arg))
                                arg_machine = mfree(arg_machine);
                        else {
                                if (!hostname_is_valid(opts.arg, 0))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Invalid machine name: %s", opts.arg);

                                r = free_and_strdup(&arg_machine, opts.arg);
                                if (r < 0)
                                        return log_oom();
                        }
                        break;

                OPTION_LONG("uuid", "UUID", "Set a specific machine UUID for the VM"):
                        r = id128_from_string_nonzero(opts.arg, &arg_uuid);
                        if (r == -ENXIO)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Machine UUID may not be all zeroes.");
                        if (r < 0)
                                return log_error_errno(r, "Invalid UUID: %s", opts.arg);
                        break;

                OPTION_GROUP("Properties"): {}

                OPTION('S', "slice", "SLICE", "Place the VM in the specified slice"): {
                        _cleanup_free_ char *mangled = NULL;

                        r = unit_name_mangle_with_suffix(opts.arg, /* operation= */ NULL, UNIT_NAME_MANGLE_WARN, ".slice", &mangled);
                        if (r < 0)
                                return log_error_errno(r, "Failed to turn '%s' into unit name: %m", opts.arg);

                        free_and_replace(arg_slice, mangled);
                        break;
                }

                OPTION_LONG("property", "NAME=VALUE", "Set scope unit property"):
                        if (strv_extend(&arg_property, opts.arg) < 0)
                                return log_oom();
                        break;

                OPTION_LONG("register", "BOOLEAN", "Register VM as machine"):
                        r = parse_tristate_argument_with_auto("--register=", opts.arg, &arg_register);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("keep-unit", NULL,
                            "Do not register a scope for the machine, reuse the service unit vmspawn is running in"):
                        arg_keep_unit = true;
                        break;

                OPTION_GROUP("User Namespacing"): {}

                OPTION_LONG("private-users", "UIDBASE[:NUIDS]",
                            "Configure the UID/GID range to map into the virtiofsd namespace"):
                        r = parse_userns_uid_range(opts.arg, &arg_uid_shift, &arg_uid_range);
                        if (r < 0)
                                return r;
                        break;

                OPTION_GROUP("Mounts"): {}

                OPTION_LONG("bind", "SOURCE[:TARGET]", "Mount a file or directory from the host into the VM"): {}
                OPTION_LONG("bind-ro", "SOURCE[:TARGET]", "Mount a file or directory, but read-only"): {
                        bool read_only = streq(opts.opt->long_code, "bind-ro");
                        r = runtime_mount_parse(&arg_runtime_mounts, opts.arg, read_only);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --%s= argument %s: %m",
                                                       opts.opt->long_code, opts.arg);
                        break;
                }

                OPTION_LONG("extra-drive", "[FORMAT:][DISKTYPE:]PATH", "Adds an additional disk to the VM"): {
                        ImageFormat format = IMAGE_FORMAT_RAW;
                        DiskType extra_disk_type = _DISK_TYPE_INVALID;
                        _cleanup_free_ char *drive_path = NULL;

                        r = parse_disk_spec(opts.arg, &format, &extra_disk_type, &drive_path);
                        if (r < 0)
                                return r;

                        if (!GREEDY_REALLOC(arg_extra_drives.drives, arg_extra_drives.n_drives + 1))
                                return log_oom();

                        arg_extra_drives.drives[arg_extra_drives.n_drives++] = (ExtraDrive) {
                                .path = TAKE_PTR(drive_path),
                                .format = format,
                                .disk_type = extra_disk_type,
                        };
                        break;
                }

                OPTION_LONG("bind-volume", "PROVIDER:VOLUME[:CONFIG][:KEY=VALUE,...]",
                            "Acquire a storage volume from a StorageProvider and attach it to the VM"): {
                        _cleanup_(bind_volume_freep) BindVolume *bv = NULL;

                        r = bind_volume_parse(opts.arg, &bv);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --bind-volume= argument '%s': %m", opts.arg);

                        if (disk_type_from_bind_volume_config(bv->config) < 0) {
                                _cleanup_free_ char *valid = NULL;
                                for (DiskType t = 0; t < _DISK_TYPE_MAX; t++)
                                        if (!strextend_with_separator(&valid, ", ", disk_type_to_string(t)))
                                                return log_oom();
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown device type '%s' for --bind-volume=. Valid values: %s.",
                                                       bv->config, valid);
                        }

                        FOREACH_ARRAY(it, arg_bind_volumes.items, arg_bind_volumes.n_items)
                                if (streq((*it)->provider, bv->provider) && streq((*it)->volume, bv->volume))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Volume '%s:%s' specified more than once for --bind-volume=.",
                                                               bv->provider, bv->volume);

                        if (!GREEDY_REALLOC(arg_bind_volumes.items, arg_bind_volumes.n_items + 1))
                                return log_oom();
                        arg_bind_volumes.items[arg_bind_volumes.n_items++] = TAKE_PTR(bv);
                        break;
                }

                OPTION_LONG("bind-user", "NAME", "Bind user from host to virtual machine"):
                        if (!valid_user_group_name(opts.arg, /* flags= */ 0))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid user name to bind: %s", opts.arg);

                        if (strv_extend(&arg_bind_user, opts.arg) < 0)
                                return log_oom();
                        break;

                OPTION_LONG("bind-user-shell", "BOOL|PATH",
                            "Configure the shell to use for --bind-user= users"): {
                        bool copy = false;
                        char *sh = NULL;
                        r = parse_user_shell(opts.arg, &sh, &copy);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Invalid user shell to bind: %s", opts.arg);

                        free_and_replace(arg_bind_user_shell, sh);
                        arg_bind_user_shell_copy = copy;
                        break;
                }

                OPTION_LONG("bind-user-group", "GROUP", "Add an auxiliary group to --bind-user= users"):
                        if (!valid_user_group_name(opts.arg, /* flags= */ 0))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid bind user auxiliary group name: %s", opts.arg);

                        if (strv_extend(&arg_bind_user_groups, opts.arg) < 0)
                                return log_oom();
                        break;

                OPTION_GROUP("Integration"): {}

                OPTION_LONG("forward-journal", "FILE|DIR", "Forward the VM's journal to the host"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_forward_journal);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("forward-journal-max-use", "BYTES", "Maximum disk space for forwarded journal"):
                        r = parse_size(opts.arg, 1024, &arg_forward_journal_max_use);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --forward-journal-max-use= value: %s", opts.arg);
                        break;

                OPTION_LONG("forward-journal-keep-free", "BYTES", "Minimum disk space to keep free"):
                        r = parse_size(opts.arg, 1024, &arg_forward_journal_keep_free);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --forward-journal-keep-free= value: %s", opts.arg);
                        break;

                OPTION_LONG("forward-journal-max-file-size", "BYTES", "Maximum size of individual journal files"):
                        r = parse_size(opts.arg, 1024, &arg_forward_journal_max_file_size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --forward-journal-max-file-size= value: %s", opts.arg);
                        break;

                OPTION_LONG("forward-journal-max-files", "N", "Maximum number of journal files to keep"):
                        r = safe_atou64(opts.arg, &arg_forward_journal_max_files);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --forward-journal-max-files= value: %s", opts.arg);
                        break;

                OPTION_LONG("pass-ssh-key", "BOOL", "Create an SSH key to access the VM"):
                        r = parse_boolean_argument("--pass-ssh-key=", opts.arg, &arg_pass_ssh_key);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("ssh-key-type", "TYPE", "Choose what type of SSH key to pass"):
                        if (isempty(opts.arg)) {
                                arg_ssh_key_type = mfree(arg_ssh_key_type);
                                break;
                        }

                        if (!string_is_safe(opts.arg, STRING_ALLOW_GLOBS))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid value for --ssh-key-type=: %s", opts.arg);

                        r = free_and_strdup_warn(&arg_ssh_key_type, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_GROUP("Input/Output"): {}

                OPTION_LONG("console", "MODE",
                            "Console mode (interactive, native, gui, read-only or headless)"):
                        arg_console_mode = console_mode_from_string(opts.arg);
                        if (arg_console_mode < 0)
                                return log_error_errno(arg_console_mode, "Failed to parse specified console mode: %s", opts.arg);
                        break;

                OPTION_LONG("console-transport", "TRANSPORT", "Console transport (virtio or serial)"):
                        arg_console_transport = console_transport_from_string(opts.arg);
                        if (arg_console_transport < 0)
                                return log_error_errno(arg_console_transport, "Failed to parse specified console transport: %s", opts.arg);
                        break;

                OPTION_LONG("qemu-gui", NULL, /* help= */ NULL):  /* Compat alias */
                        arg_console_mode = CONSOLE_GUI;
                        break;

                OPTION_LONG("background", "COLOR", "Set ANSI color for background"):
                        r = parse_background_argument(opts.arg, &arg_background);
                        if (r < 0)
                                return r;
                        break;

                OPTION_GROUP("Credentials"): {}

                OPTION_LONG("set-credential", "ID:VALUE", "Pass a credential with literal value to the VM"):
                        r = machine_credential_set(&arg_credentials, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("load-credential", "ID:PATH",
                            "Load credential for the VM from file or AF_UNIX stream socket"):
                        r = machine_credential_load(&arg_credentials, opts.arg);
                        if (r < 0)
                                return r;
                        break;
                }

        /* Drop duplicate --bind-user= and --bind-user-group= entries */
        strv_uniq(arg_bind_user);
        strv_uniq(arg_bind_user_groups);

        if (arg_bind_user_shell && strv_isempty(arg_bind_user))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot use --bind-user-shell= without --bind-user=");

        if (!strv_isempty(arg_bind_user_groups) && strv_isempty(arg_bind_user))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot use --bind-user-group= without --bind-user=");

        if (arg_ram_max > 0 && arg_ram_max < arg_ram)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Maximum RAM size must be greater than or equal to initial RAM size");

        if (arg_ram_slots > 0 && arg_ram_max == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Memory hotplug slots require a maximum RAM size");

        if ((arg_forward_journal_max_use != UINT64_MAX ||
             arg_forward_journal_keep_free != UINT64_MAX ||
             arg_forward_journal_max_file_size != UINT64_MAX ||
             arg_forward_journal_max_files != UINT64_MAX) && !arg_forward_journal)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--forward-journal-max-use=/--forward-journal-keep-free=/--forward-journal-max-file-size=/--forward-journal-max-files= require --forward-journal=.");

        if (arg_ephemeral && arg_extra_drives.n_drives > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot use --ephemeral with --extra-drive=");

        if (arg_uid_shift != UID_INVALID && !arg_directory)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--private-users= is only supported in combination with --directory=.");

        if (arg_directory && arg_uid_shift == UID_INVALID) {
                struct stat st;
                if (stat(arg_directory, &st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", arg_directory);

                r = stat_verify_directory(&st);
                if (r < 0)
                        return log_error_errno(r, "'%s' is not a directory: %m", arg_directory);

                arg_uid_shift = st.st_uid;
                arg_uid_range = 0x10000;
        }

        char **args = option_parser_get_args(&opts);
        if (!strv_isempty(args)) {
                arg_kernel_cmdline_extra = strv_copy(args);
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

        assert(source);
        assert(fd >= 0);
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
        assert(s);
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

static bool smbios_supported(void) {
        /* SMBIOS is always available on x86 (via SeaBIOS fallback), but on
         * other architectures it requires UEFI firmware to be loaded. */
        return ARCHITECTURE_SUPPORTS_SMBIOS &&
               (IN_SET(native_architecture(), ARCHITECTURE_X86, ARCHITECTURE_X86_64) || arg_firmware_type == FIRMWARE_UEFI);
}

static int add_vsock_credential(int vsock_fd) {
        assert(vsock_fd >= 0);

        union sockaddr_union addr;
        socklen_t addr_len = sizeof addr.vm;
        if (getsockname(vsock_fd, &addr.sa, &addr_len) < 0)
                return -errno;

        assert(addr_len >= sizeof addr.vm);
        assert(addr.vm.svm_family == AF_VSOCK);

        _cleanup_free_ char *value = NULL;
        if (asprintf(&value, "vsock-stream:%u:%u", (unsigned) VMADDR_CID_HOST, addr.vm.svm_port) < 0)
                return -ENOMEM;

        return machine_credential_add(&arg_credentials, "vmm.notify_socket", value, SIZE_MAX);
}

static int cmdline_add_kernel_cmdline(char ***cmdline, int smbios_dir_fd, const char *smbios_dir) {
        int r;

        assert(cmdline);
        assert(smbios_dir_fd >= 0);
        assert(smbios_dir);

        if (strv_isempty(arg_kernel_cmdline_extra))
                return 0;

        _cleanup_free_ char *kcl = strv_join(arg_kernel_cmdline_extra, " ");
        if (!kcl)
                return log_oom();

        size_t kcl_len = strlen(kcl);
        if (kcl_len >= KERNEL_CMDLINE_SIZE)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG),
                                       "Kernel command line length (%zu) exceeds the kernel's COMMAND_LINE_SIZE (%d).",
                                       kcl_len, KERNEL_CMDLINE_SIZE);

        if (arg_linux_image_type >= 0 && arg_linux_image_type != KERNEL_IMAGE_TYPE_UKI) {
                if (strv_extend_many(cmdline, "-append", kcl) < 0)
                        return log_oom();
        } else {
                if (!smbios_supported()) {
                        log_warning("Cannot append extra args to kernel cmdline, native architecture doesn't support SMBIOS, ignoring.");
                        return 0;
                }

                FOREACH_STRING(id, "io.systemd.stub.kernel-cmdline-extra", "io.systemd.boot.kernel-cmdline-extra") {
                        _cleanup_free_ char *content = strjoin(id, "=", kcl);
                        if (!content)
                                return log_oom();

                        r = write_string_file_at(
                                        smbios_dir_fd, id, content,
                                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE|WRITE_STRING_FILE_MODE_0600);
                        if (r < 0)
                                return log_error_errno(r, "Failed to write smbios kernel command line to file: %m");

                        _cleanup_free_ char *p = path_join(smbios_dir, id);
                        if (!p)
                                return log_oom();

                        if (strv_extend(cmdline, "-smbios") < 0)
                                return log_oom();

                        if (strv_extend_joined(cmdline, "type=11,path=", p) < 0)
                                return log_oom();
                }
        }

        return 0;
}

static int cmdline_add_credentials(char ***cmdline, int smbios_dir_fd, const char *smbios_dir) {
        int r;

        assert(cmdline);
        assert(smbios_dir_fd >= 0);
        assert(smbios_dir);

        FOREACH_ARRAY(cred, arg_credentials.credentials, arg_credentials.n_credentials) {
                _cleanup_free_ char *cred_data_b64 = NULL;
                ssize_t n;

                n = base64mem(cred->data, cred->size, &cred_data_b64);
                if (n < 0)
                        return log_oom();

                if (smbios_supported()) {
                        _cleanup_free_ char *content = NULL;
                        if (asprintf(&content, "io.systemd.credential.binary:%s=%s", cred->id, cred_data_b64) < 0)
                                return log_oom();

                        r = write_string_file_at(
                                        smbios_dir_fd, cred->id, content,
                                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_AVOID_NEWLINE|WRITE_STRING_FILE_MODE_0600);
                        if (r < 0)
                                return log_error_errno(r, "Failed to write smbios credential file: %m");

                        _cleanup_free_ char *p = path_join(smbios_dir, cred->id);
                        if (!p)
                                return log_oom();

                        if (strv_extend(cmdline, "-smbios") < 0)
                                return log_oom();

                        if (strv_extend_joined(cmdline, "type=11,path=", p) < 0)
                                return log_oom();

                } else if (ARCHITECTURE_SUPPORTS_FW_CFG) {
                        /* fw_cfg keys are limited to 55 characters */
                        _cleanup_free_ char *key = strjoin("opt/io.systemd.credentials/", cred->id);
                        if (!key)
                                return log_oom();

                        if (strlen(key) <= QEMU_FW_CFG_MAX_KEY_LEN) {
                                r = write_data_file_atomic_at(
                                                smbios_dir_fd, cred->id,
                                                &IOVEC_MAKE(cred->data, cred->size),
                                                WRITE_DATA_FILE_MODE_0400);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to write fw_cfg credential file: %m");

                                _cleanup_free_ char *p = path_join(smbios_dir, cred->id);
                                if (!p)
                                        return log_oom();

                                if (strv_extend(cmdline, "-fw_cfg") < 0)
                                        return log_oom();

                                if (strv_extendf(cmdline, "name=%s,file=%s", key, p) < 0)
                                        return log_oom();

                                continue;
                        }

                        /* Fall through to kernel command line if key is too long */
                        log_notice("fw_cfg key '%s' exceeds %d character limit, passing credential via kernel command line. "
                                   "Note that this will make literal credentials readable to unprivileged userspace.",
                                   key, QEMU_FW_CFG_MAX_KEY_LEN);

                        if (arg_linux_image_type < 0)
                                return log_error_errno(
                                                SYNTHETIC_ERRNO(E2BIG),
                                                "Cannot pass credential '%s' to VM, fw_cfg key exceeds %d character limit and no kernel for direct boot specified.",
                                                cred->id,
                                                QEMU_FW_CFG_MAX_KEY_LEN);

                        if (strv_extendf(&arg_kernel_cmdline_extra,
                                         "systemd.set_credential_binary=%s:%s", cred->id, cred_data_b64) < 0)
                                return log_oom();

                } else if (arg_linux_image_type >= 0) {
                        log_notice("Both SMBIOS and fw_cfg are not supported, passing credential via kernel command line. "
                                   "Note that this will make literal credentials readable to unprivileged userspace.");
                        if (strv_extendf(&arg_kernel_cmdline_extra,
                                         "systemd.set_credential_binary=%s:%s", cred->id, cred_data_b64) < 0)
                                return log_oom();
                } else
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(EOPNOTSUPP),
                                        "Cannot pass credential '%s' to VM, native architecture doesn't support SMBIOS or fw_cfg and no kernel for direct boot specified.",
                                        cred->id);
        }

        return 0;
}

static int cmdline_add_smbios11(char ***cmdline, int smbios_dir_fd, const char *smbios_dir) {
        int r;

        assert(cmdline);
        assert(smbios_dir_fd >= 0);
        assert(smbios_dir);

        if (strv_isempty(arg_smbios11))
                return 0;

        if (!smbios_supported()) {
                log_warning("Cannot issue SMBIOS Type #11 strings, native architecture doesn't support SMBIOS, ignoring.");
                return 0;
        }

        STRV_FOREACH(i, arg_smbios11) {
                _cleanup_(unlink_and_freep) char *p = NULL;

                r = tempfn_random_child(smbios_dir, "smbios11", &p);
                if (r < 0)
                        return r;

                _cleanup_free_ char *fn = NULL;
                r = path_extract_filename(p, &fn);
                if (r < 0)
                        return r;

                r = write_string_file_at(
                                smbios_dir_fd, fn, *i,
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
        assert(sd_socket_activate);

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

        r = manufacture_swtpm(state_dir, /* secret= */ NULL);
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **argv = NULL;
        argv = strv_new(sd_socket_activate, "--listen", listen_address, swtpm, "socket", "--tpm2", "--tpmstate");
        if (!argv)
                return log_oom();

        r = strv_extend_joined(&argv, "dir=", state_dir);
        if (r < 0)
                return log_oom();

        r = strv_extend_many(&argv, "--ctrl", "type=unixio,fd=3");
        if (r < 0)
                return log_oom();

        r = fork_notify(argv, /* child_handler= */ NULL, /* child_userdata= */ NULL, ret_pidref);
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

        assert(ret);

        r = find_executable("virtiofsd", ret);
        if (r >= 0)
                return 0;
        if (r != -ENOENT)
                return log_error_errno(r, "Error while searching for virtiofsd: %m");

        FOREACH_STRING(file, "/usr/libexec/virtiofsd", "/usr/lib/virtiofsd") {
                if (access(file, X_OK) >= 0) {
                        _cleanup_free_ char *copy = strdup(file);
                        if (!copy)
                                return log_oom();

                        *ret = TAKE_PTR(copy);
                        return 0;
                }

                if (!IN_SET(errno, ENOENT, EACCES))
                        return log_error_errno(errno, "Error while searching for virtiofsd: %m");
        }

        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Failed to find virtiofsd binary.");
}

static int start_virtiofsd(
                const char *scope,
                const char *directory,
                uid_t source_uid,
                uid_t target_uid,
                uid_t uid_range,
                const char *runtime_dir,
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

        union sockaddr_union su;
        r = sockaddr_un_set_path(&su.un, listen_address);
        if (r < 0)
                return r;

        _cleanup_close_ int sock = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (sock < 0)
                return log_error_errno(errno, "Failed to create unix socket: %m");

        if (bind(sock, &su.sa, r) < 0)
                return log_error_errno(errno, "Failed to bind unix socket to '%s': %m", listen_address);

        if (listen(sock, SOMAXCONN_DELUXE) < 0)
                return log_error_errno(errno, "Failed to listen on unix socket '%s': %m", listen_address);

        _cleanup_free_ char *sockstr = NULL;
        if (asprintf(&sockstr, "%i", sock) < 0)
                return log_oom();

        /* QEMU doesn't support submounts so don't announce them */
        _cleanup_strv_free_ char **argv = strv_new(
                        virtiofsd,
                        "--shared-dir", source_uid == FOREIGN_UID_MIN ? "/run/systemd/mount-rootfs" : directory,
                        "--xattr",
                        "--fd", sockstr,
                        "--no-announce-submounts",
                        "--log-level=error",
                        "--modcaps=-mknod");
        if (!argv)
                return log_oom();

        _cleanup_close_ int userns_fd = -EBADF, mapped_fd = -EBADF;

        if (source_uid == FOREIGN_UID_MIN) {
                assert(target_uid == 0);
                assert(uid_range == 0x10000);

                userns_fd = nsresource_allocate_userns(/* vl= */ NULL, /* name= */ NULL, NSRESOURCE_UIDS_64K);
                if (userns_fd < 0)
                        return log_error_errno(userns_fd, "Failed to allocate user namespace for virtiofsd: %m");

                _cleanup_close_ int directory_fd = open(directory, O_DIRECTORY|O_CLOEXEC|O_PATH);
                if (directory_fd < 0)
                        return log_error_errno(directory_fd, "Failed to open '%s': %m", directory);

                r = mountfsd_mount_directory_fd(/* vl= */ NULL, directory_fd, userns_fd, DISSECT_IMAGE_FOREIGN_UID, &mapped_fd);
                if (r < 0)
                        return r;

        } else if (!IN_SET(source_uid, FOREIGN_UID_MIN, UID_INVALID) && target_uid != UID_INVALID && uid_range != UID_INVALID) {
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

        r = pidref_safe_fork_full(
                        "(virtiofsd)",
                        (const int[3]) { -EBADF, STDOUT_FILENO, STDERR_FILENO },
                        (int[]) { sock, userns_fd, mapped_fd },
                        source_uid == FOREIGN_UID_MIN ? 3 : 1,
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_CLOSE_ALL_FDS|FORK_REOPEN_LOG|FORK_REARRANGE_STDIO,
                        ret_pidref);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */

                r = namespace_enter(
                                /* pidns_fd= */ -EBADF,
                                /* mntns_fd= */ -EBADF,
                                /* netns_fd= */ -EBADF,
                                userns_fd,
                                /* root_fd= */ -EBADF);
                if (r < 0) {
                        log_error_errno(r, "Failed to enter user namespace for virtiofsd: %m");
                        _exit(EXIT_FAILURE);
                }

                if (userns_fd >= 0 && unshare(CLONE_NEWNS) < 0) {
                        log_error_errno(errno, "Failed to unshare mount namespace %m");
                        _exit(EXIT_FAILURE);
                }

                if (mapped_fd >= 0 && move_mount(mapped_fd, "", AT_FDCWD, "/run/systemd/mount-rootfs", MOVE_MOUNT_F_EMPTY_PATH) < 0) {
                        log_error_errno(errno, "Failed to move mount file descriptor to '/run/systemd/mount-rootfs': %m");
                        _exit(EXIT_FAILURE);
                }

                r = fd_cloexec(sock, false);
                if (r < 0) {
                        log_error_errno(r, "Failed to disable cloexec on socket: %m");
                        _exit(EXIT_FAILURE);
                }

                invoke_callout_binary(argv[0], argv);
                log_error_errno(errno, "Failed to execute '%s': %m", argv[0]);
                _exit(EXIT_FAILURE);
        }

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

        if (strv_find_startswith(arg_kernel_cmdline_extra, "root=") ||
            strv_find_startswith(arg_kernel_cmdline_extra, "mount.usr="))
                return 0;

        _cleanup_free_ char *root = NULL;
        r = discover_root(&root);
        if (r < 0)
                return r;

        log_debug("Determined root file system '%s' from dissected image", root);

        if (strv_consume(&arg_kernel_cmdline_extra, TAKE_PTR(root)) < 0)
                return log_oom();

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

static int make_sidecar_path(const char *suffix, char **ret) {
        int r;

        assert(suffix);
        assert(ret);

        const char *p = ASSERT_PTR(arg_image ?: arg_directory);

        _cleanup_free_ char *parent = NULL, *filename = NULL;
        r = path_split_prefix_filename(p, &parent, &filename);
        if (r < 0)
                return log_error_errno(r, "Failed to extract parent directory and filename from '%s': %m", p);

        if (!strextend(&filename, suffix))
                return log_oom();

        _cleanup_free_ char *j = path_join(parent, filename);
        if (!j)
                return log_oom();

        *ret = TAKE_PTR(j);
        return 0;
}

/* Device serial numbers have length limits (e.g. 20 for NVMe, 30 for SCSI).
 * If the filename fits, use it directly; otherwise hash it with SHA-256 and
 * take the first max_len hex characters. max_len must be even and <= 64.
 * The filename should already be QEMU-escaped (commas doubled) so that the
 * result can be embedded directly in a -device argument. */
static int disk_serial(const char *filename, size_t max_len, char **ret) {
        assert(filename);
        assert(ret);
        assert(max_len % 2 == 0);
        assert(max_len <= SHA256_DIGEST_SIZE * 2);

        if (strlen(filename) <= max_len)
                return strdup_to(ret, filename);

        uint8_t hash[SHA256_DIGEST_SIZE];
        sha256_direct(filename, strlen(filename), hash);

        _cleanup_free_ char *serial = hexmem(hash, max_len / 2);
        if (!serial)
                return -ENOMEM;

        *ret = TAKE_PTR(serial);
        return 0;
}

static int cmdline_add_ovmf(FILE *config_file, const OvmfConfig *ovmf_config, char **ret_ovmf_vars) {
        int r;

        assert(config_file);
        assert(ret_ovmf_vars);

        if (!ovmf_config) {
                *ret_ovmf_vars = NULL;
                return 0;
        }

        r = qemu_config_section(config_file, "drive", "ovmf-code",
                                "if", "pflash",
                                "format", ovmf_config_format(ovmf_config),
                                "readonly", "on",
                                "file", ovmf_config->path);
        if (r < 0)
                return r;

        if (!ovmf_config->vars && !arg_efi_nvram_template) {
                *ret_ovmf_vars = NULL;
                return 0;
        }

        if (arg_efi_nvram_state_mode == STATE_AUTO && !arg_ephemeral) {
                assert(!arg_efi_nvram_state_path);

                r = make_sidecar_path(".efinvramstate", &arg_efi_nvram_state_path);
                if (r < 0)
                        return r;

                log_debug("Storing EFI NVRAM state persistently under '%s'.", arg_efi_nvram_state_path);
        }

        const char *vars_source = arg_efi_nvram_template ?: ovmf_config->vars;
        _cleanup_close_ int target_fd = -EBADF;
        _cleanup_(unlink_and_freep) char *destroy_path = NULL;
        bool newly_created;
        const char *state;
        if (arg_efi_nvram_state_path) {
                _cleanup_free_ char *d = strdup(arg_efi_nvram_state_path);
                if (!d)
                        return log_oom();

                target_fd = openat_report_new(AT_FDCWD, arg_efi_nvram_state_path, O_WRONLY|O_CREAT|O_CLOEXEC, 0600, &newly_created);
                if (target_fd < 0)
                        return log_error_errno(target_fd, "Failed to open file for OVMF vars at %s: %m", arg_efi_nvram_state_path);

                if (newly_created)
                        destroy_path = TAKE_PTR(d);

                r = fd_verify_regular(target_fd);
                if (r < 0)
                        return log_error_errno(r, "Not a regular file for OVMF variables at %s: %m", arg_efi_nvram_state_path);

                state = arg_efi_nvram_state_path;
        } else {
                _cleanup_free_ char *t = NULL;
                r = tempfn_random_child(/* p= */ NULL, "vmspawn-", &t);
                if (r < 0)
                        return log_error_errno(r, "Failed to create temporary filename: %m");

                target_fd = open(t, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600);
                if (target_fd < 0)
                        return log_error_errno(errno, "Failed to create regular file for OVMF vars at %s: %m", t);

                newly_created = true;
                state = *ret_ovmf_vars = TAKE_PTR(t);
        }

        if (newly_created) {
                _cleanup_close_ int source_fd = open(vars_source, O_RDONLY|O_CLOEXEC);
                if (source_fd < 0)
                        return log_error_errno(errno, "Failed to open OVMF vars file %s: %m", vars_source);

                r = copy_bytes(source_fd, target_fd, UINT64_MAX, COPY_REFLINK);
                if (r < 0)
                        return log_error_errno(r, "Failed to copy bytes from %s to %s: %m", vars_source, state);

                /* This isn't always available so don't raise an error if it fails */
                (void) copy_times(source_fd, target_fd, 0);
        }

        destroy_path = mfree(destroy_path); /* disarm auto-destroy */

        /* Mark the UEFI variable store pflash as requiring SMM access. This
         * prevents the guest OS from writing to pflash directly, ensuring all
         * variable updates go through the firmware's validation checks. Without
         * this, secure boot keys could be overwritten by the OS. */
        if (ARCHITECTURE_SUPPORTS_SMM) {
                r = qemu_config_section(config_file, "global", /* id= */ NULL,
                                        "driver", "cfi.pflash01",
                                        "property", "secure",
                                        "value", "on");
                if (r < 0)
                        return r;
        }

        r = qemu_config_section(config_file, "drive", "ovmf-vars",
                                "file", state,
                                "if", "pflash",
                                "format", ovmf_config_format(ovmf_config));
        if (r < 0)
                return r;

        return 0;
}

/* Create a QMP control socketpair, add QEMU's end to pass_fds, and write the chardev + monitor
 * config sections. Returns with bridge_fds populated: [0] is vmspawn's end, [1] is QEMU's end
 * (also in pass_fds). FORK_CLOEXEC_OFF clears CLOEXEC on pass_fds in the child. */
static int qemu_config_add_qmp_monitor(FILE *config_file, int bridge_fds[2], int **pass_fds, size_t *n_pass_fds) {
        int r;

        assert(config_file);
        assert(bridge_fds);
        assert(pass_fds);
        assert(n_pass_fds);

        if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, bridge_fds) < 0)
                return log_error_errno(errno, "Failed to create QMP socketpair: %m");

        if (!GREEDY_REALLOC(*pass_fds, *n_pass_fds + 1))
                return log_oom();
        (*pass_fds)[(*n_pass_fds)++] = bridge_fds[1];

        r = qemu_config_section(config_file, "chardev", "qmp",
                                "backend", "socket");
        if (r < 0)
                return r;

        r = qemu_config_keyf(config_file, "fd", "%d", bridge_fds[1]);
        if (r < 0)
                return r;

        return qemu_config_section(config_file, "mon", "qmp",
                                   "chardev", "qmp",
                                   "mode", "control");
}

static int resolve_disk_driver(DiskType dt, const char *filename, DriveInfo *info) {
        size_t serial_max;
        int r;

        assert(filename);
        assert(info);

        switch (dt) {
        case DISK_TYPE_VIRTIO_BLK:
                serial_max = DISK_SERIAL_MAX_LEN_VIRTIO_BLK;
                break;
        case DISK_TYPE_VIRTIO_SCSI:
                serial_max = DISK_SERIAL_MAX_LEN_SCSI;
                break;
        case DISK_TYPE_NVME:
                serial_max = DISK_SERIAL_MAX_LEN_NVME;
                break;
        case DISK_TYPE_VIRTIO_SCSI_CDROM:
                serial_max = DISK_SERIAL_MAX_LEN_SCSI;
                info->flags |= QMP_DRIVE_READ_ONLY;
                break;
        default:
                assert_not_reached();
        }

        info->disk_driver = strdup(ASSERT_PTR(qemu_device_driver_to_string(dt)));
        if (!info->disk_driver)
                return log_oom();

        r = disk_serial(filename, serial_max, &info->serial);
        if (r < 0)
                return r;

        return 0;
}

static int prepare_primary_drive(const char *runtime_dir, DriveInfos *drives) {
        int r;

        assert(runtime_dir);
        assert(drives);

        if (!arg_image)
                return 0;

        _cleanup_free_ char *image_fn = NULL;
        r = path_extract_filename(arg_image, &image_fn);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from path '%s': %m", arg_image);

        _cleanup_(drive_info_unrefp) DriveInfo *d = drive_info_new();
        if (!d)
                return log_oom();

        r = resolve_disk_driver(arg_image_disk_type, image_fn, d);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve disk driver for '%s': %m", image_fn);

        int open_flags = ((arg_ephemeral || FLAGS_SET(d->flags, QMP_DRIVE_READ_ONLY)) ? O_RDONLY : O_RDWR) | O_CLOEXEC | O_NOCTTY;

        _cleanup_close_ int image_fd = open(arg_image, open_flags);
        if (image_fd < 0)
                return log_error_errno(errno, "Failed to open '%s': %m", arg_image);

        struct stat st;
        if (fstat(image_fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat '%s': %m", arg_image);

        r = stat_verify_regular_or_block(&st);
        if (r < 0)
                return log_error_errno(r, "Expected regular file or block device for image: %s", arg_image);

        d->path = strdup(arg_image);
        d->format = strdup(ASSERT_PTR(image_format_to_string(arg_image_format)));
        if (!d->path || !d->format)
                return log_oom();
        d->fd = TAKE_FD(image_fd);
        if (S_ISBLK(st.st_mode))
                d->flags |= QMP_DRIVE_BLOCK_DEVICE;
        if (arg_discard_disk && !FLAGS_SET(d->flags, QMP_DRIVE_READ_ONLY))
                d->flags |= QMP_DRIVE_DISCARD;
        d->flags |= QMP_DRIVE_BOOT;

        /* For ephemeral mode, create an anonymous overlay file. QEMU will format it
         * as qcow2 via blockdev-create, so no filesystem path is needed.
         * Skip for read-only drives (e.g. CDROM) where overlays are not meaningful. */
        if (arg_ephemeral && !FLAGS_SET(d->flags, QMP_DRIVE_READ_ONLY)) {
                _cleanup_close_ int overlay_fd = open(runtime_dir, O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
                if (overlay_fd < 0) {
                        if (!ERRNO_IS_NOT_SUPPORTED(errno))
                                return log_error_errno(errno, "Failed to create ephemeral overlay in '%s': %m", runtime_dir);

                        /* Fallback to memfd if O_TMPFILE is not supported */
                        overlay_fd = memfd_new("vmspawn-overlay");
                        if (overlay_fd < 0)
                                return log_error_errno(overlay_fd, "Failed to create ephemeral overlay via memfd: %m");
                }
                d->overlay_fd = TAKE_FD(overlay_fd);
                d->flags |= QMP_DRIVE_NO_FLUSH;
        }

        drives->drives[drives->n_drives++] = TAKE_PTR(d);
        return 0;
}

static int prepare_extra_drives(DriveInfos *drives) {
        int r;

        assert(drives);

        FOREACH_ARRAY(drive, arg_extra_drives.drives, arg_extra_drives.n_drives) {
                _cleanup_free_ char *drive_fn = NULL;
                r = path_extract_filename(drive->path, &drive_fn);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from path '%s': %m", drive->path);

                DiskType dt = drive->disk_type >= 0 ? drive->disk_type : arg_image_disk_type;

                _cleanup_(drive_info_unrefp) DriveInfo *d = drive_info_new();
                if (!d)
                        return log_oom();

                r = resolve_disk_driver(dt, drive_fn, d);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve disk driver for '%s': %m", drive_fn);

                _cleanup_close_ int drive_fd = open(drive->path, (FLAGS_SET(d->flags, QMP_DRIVE_READ_ONLY) ? O_RDONLY : O_RDWR) | O_CLOEXEC | O_NOCTTY);
                if (drive_fd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", drive->path);

                struct stat drive_st;
                if (fstat(drive_fd, &drive_st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", drive->path);
                r = stat_verify_regular_or_block(&drive_st);
                if (r < 0)
                        return log_error_errno(r, "Expected regular file or block device, not '%s'.", drive->path);
                if (S_ISBLK(drive_st.st_mode) && drive->format == IMAGE_FORMAT_QCOW2)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Block device '%s' cannot be used with 'qcow2' format, only 'raw' is supported.",
                                               drive->path);

                d->path = strdup(drive->path);
                d->format = strdup(ASSERT_PTR(image_format_to_string(drive->format)));
                if (!d->path || !d->format)
                        return log_oom();
                d->fd = TAKE_FD(drive_fd);
                if (S_ISBLK(drive_st.st_mode))
                        d->flags |= QMP_DRIVE_BLOCK_DEVICE;
                d->flags |= QMP_DRIVE_NO_FLUSH;

                drives->drives[drives->n_drives++] = TAKE_PTR(d);
        }

        return 0;
}

/* Assign PCIe root port names to devices. The ports were pre-allocated in the config
 * file. Each PCI device that will be hotplugged via QMP device_add gets a port. */
static int assign_pcie_ports(MachineConfig *c) {
        assert(c);

        if (!ARCHITECTURE_NEEDS_PCIE_ROOT_PORTS)
                return 0;

        DriveInfos *drives = &c->drives;
        NetworkInfo *network = &c->network;
        VirtiofsInfos *virtiofs = &c->virtiofs;
        VsockInfo *vsock = &c->vsock;

        size_t port = 0;

        /* Non-SCSI drives get individual ports. SCSI controllers (if any) allocate
         * from the hotplug-spares pool on demand at device-add time. */
        FOREACH_ARRAY(d, drives->drives, drives->n_drives) {
                DriveInfo *drive = *d;
                if (STR_IN_SET(drive->disk_driver, "scsi-hd", "scsi-cd"))
                        continue;
                if (asprintf(&drive->pcie_port, "vmspawn-pcieport-%zu", port++) < 0)
                        return log_oom();
        }

        if (network->type)
                if (asprintf(&network->pcie_port, "vmspawn-pcieport-%zu", port++) < 0)
                        return log_oom();

        FOREACH_ARRAY(v, virtiofs->entries, virtiofs->n_entries)
                if (asprintf(&v->pcie_port, "vmspawn-pcieport-%zu", port++) < 0)
                        return log_oom();

        if (vsock->fd >= 0)
                if (asprintf(&vsock->pcie_port, "vmspawn-pcieport-%zu", port++) < 0)
                        return log_oom();

        return 0;
}

static int prepare_device_info(const char *runtime_dir, MachineConfig *c) {
        int r;

        assert(runtime_dir);
        assert(c);

        DriveInfos *drives = &c->drives;

        /* Build drive info for QMP-based setup. vmspawn opens all image files and
         * passes fds to QEMU via add-fd — QEMU never needs filesystem access. */
        drives->drives = new0(DriveInfo*, 1 + arg_extra_drives.n_drives + arg_bind_volumes.n_items);
        if (!drives->drives)
                return log_oom();

        r = prepare_primary_drive(runtime_dir, drives);
        if (r < 0)
                return r;

        r = prepare_extra_drives(drives);
        if (r < 0)
                return r;

        r = vmspawn_bind_volume_prepare_boot(arg_runtime_scope, &arg_bind_volumes, drives);
        if (r < 0)
                return r;

        return assign_pcie_ports(c);
}

static int run_virtual_machine(int kvm_device_fd, int vhost_device_fd) {
        _cleanup_(ovmf_config_freep) OvmfConfig *ovmf_config = NULL;
        _cleanup_free_ char *qemu_binary = NULL, *mem = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *ssh_private_key_path = NULL, *ssh_public_key_path = NULL;
        _cleanup_(rm_rf_subvolume_and_freep) char *snapshot_directory = NULL;
        _cleanup_(release_lock_file) LockFile tree_global_lock = LOCK_FILE_INIT, tree_local_lock = LOCK_FILE_INIT;
        _cleanup_close_ int notify_sock_fd = -EBADF;
        _cleanup_strv_free_ char **cmdline = NULL;
        _cleanup_free_ int *pass_fds = NULL;
        _cleanup_(machine_config_done) MachineConfig config = {
                .network = { .fd = -EBADF },
                .vsock   = { .fd = -EBADF },
        };
        sd_event_source **children = NULL;
        size_t n_children = 0, n_pass_fds = 0;
        int r;

        CLEANUP_ARRAY(children, n_children, fork_notify_terminate_many);

        polkit_agent_open();

        /* Registration always happens on the system bus */
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *system_bus = NULL;
        if (arg_register != 0 || arg_runtime_scope == RUNTIME_SCOPE_SYSTEM) {
                r = sd_bus_default_system(&system_bus);
                if (r < 0)
                        return log_error_errno(r, "Failed to open system bus: %m");

                r = sd_bus_set_close_on_exit(system_bus, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to disable close-on-exit behaviour: %m");

                (void) sd_bus_set_allow_interactive_authorization(system_bus, arg_ask_password);
        }

        /* Scope allocation and machine registration happen on the user bus if we are unpriv, otherwise system bus. */
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *user_bus = NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *runtime_bus = NULL;
        if (arg_register != 0 || !arg_keep_unit) {
                if (arg_runtime_scope == RUNTIME_SCOPE_SYSTEM)
                        runtime_bus = sd_bus_ref(system_bus);
                else {
                        r = sd_bus_default_user(&user_bus);
                        if (r < 0)
                                return log_error_errno(r, "Failed to open user bus: %m");

                        r = sd_bus_set_close_on_exit(user_bus, false);
                        if (r < 0)
                                return log_error_errno(r, "Failed to disable close-on-exit behaviour: %m");

                        runtime_bus = sd_bus_ref(user_bus);
                }
        }

        bool use_kvm = arg_kvm > 0;
        if (arg_kvm < 0) {
                r = qemu_check_kvm_support();
                if (r < 0)
                        return log_error_errno(r, "Failed to check for KVM support: %m");
                use_kvm = r;
        }

        if (arg_firmware_type == FIRMWARE_UEFI) {
                if (arg_firmware)
                        r = load_ovmf_config(arg_firmware, &ovmf_config);
                else
                        r = find_ovmf_config(arg_firmware_features_include, arg_firmware_features_exclude, &ovmf_config, /* ret_firmware_json= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to find OVMF config: %m");

                if (set_contains(arg_firmware_features_include, "secure-boot") && !ovmf_config->supports_sb)
                        return log_error_errno(SYNTHETIC_ERRNO(EMEDIUMTYPE),
                                               "Secure Boot requested, but selected OVMF firmware doesn't support it.");

                log_debug("Using OVMF firmware %s Secure Boot support.", ovmf_config->supports_sb ? "with" : "without");
        }

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

        r = find_qemu_binary(&qemu_binary);
        if (r == -EOPNOTSUPP)
                return log_error_errno(r, "Native architecture is not supported by qemu.");
        if (r < 0)
                return log_error_errno(r, "Failed to find QEMU binary: %m");

        if (asprintf(&mem, "%" PRIu64 "M", DIV_ROUND_UP(arg_ram, U64_MB)) < 0)
                return log_oom();

        /* Create our runtime directory. We need this for the QMP varlink control socket, the QEMU
         * config file, TPM state, virtiofsd sockets, runtime mounts, and SSH key material. */
        _cleanup_free_ char *runtime_dir = NULL, *runtime_dir_suffix = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir_destroy = NULL;

        runtime_dir_suffix = path_join("systemd/vmspawn", arg_machine);
        if (!runtime_dir_suffix)
                return log_oom();

        r = runtime_directory_make(arg_runtime_scope, runtime_dir_suffix, &runtime_dir, &runtime_dir_destroy);
        if (r < 0)
                return log_error_errno(r, "Failed to create runtime directory: %m");

        /* If a previous vmspawn instance was killed without cleanup (e.g. SIGKILL), the directory may
         * already exist with stale contents. This is harmless: varlink's sockaddr_un_unlink() removes stale
         * sockets before bind(), and other files (QEMU config, SSH keys) are created fresh. This matches
         * nspawn's approach of not proactively cleaning stale runtime directories. */

        log_debug("Using runtime directory: %s", runtime_dir);

        /* Build a QEMU config file for -readconfig. Items that can be expressed as QemuOpts sections go
         * here; things that require cmdline-only switches (e.g. -kernel, -smbios, -nographic, --add-fd)
         * are added to the cmdline strv below. */
        _cleanup_fclose_ FILE *config_file = NULL;
        _cleanup_(unlink_and_freep) char *config_path = NULL;
        r = fopen_temporary_child(runtime_dir, &config_file, &config_path);
        if (r < 0)
                return log_error_errno(r, "Failed to create QEMU config file: %m");

        r = qemu_config_section(config_file, "machine", /* id= */ NULL,
                                "type", QEMU_MACHINE_TYPE);
        if (r < 0)
                return r;

        if (ovmf_config && ARCHITECTURE_SUPPORTS_SMM) {
                r = qemu_config_key(config_file, "smm", on_off(ovmf_config->supports_sb));
                if (r < 0)
                        return r;
        }

        if (ARCHITECTURE_SUPPORTS_CXL) {
                r = qemu_config_key(config_file, "cxl", "on");
                if (r < 0)
                        return r;
        }

        if (arg_directory || arg_runtime_mounts.n_mounts != 0) {
                r = qemu_config_key(config_file, "memory-backend", "mem");
                if (r < 0)
                        return r;
        }

        if (ARCHITECTURE_SUPPORTS_HPET) {
                r = qemu_config_key(config_file, "hpet", "off");
                if (r < 0)
                        return r;
        }

        r = qemu_config_section(config_file, "smp-opts", /* id= */ NULL,
                                "cpus", arg_cpus ?: "1");
        if (r < 0)
                return r;

        r = qemu_config_section(config_file, "memory", /* id= */ NULL,
                                "size", mem);
        if (r < 0)
                return r;

        if (arg_ram_max > 0) {
                r = qemu_config_keyf(config_file, "maxmem", "%" PRIu64 "M", DIV_ROUND_UP(arg_ram_max, U64_MB));
                if (r < 0)
                        return r;

                r = qemu_config_keyf(config_file, "slots", "%u", arg_ram_slots > 0 ? arg_ram_slots : 1u);
                if (r < 0)
                        return r;
        }

        r = qemu_config_section(config_file, "object", "rng0",
                                "qom-type", "rng-random",
                                "filename", "/dev/urandom");
        if (r < 0)
                return r;

        r = qemu_config_section(config_file, "device", "rng-device0",
                                "driver", "virtio-rng-pci",
                                "rng", "rng0");
        if (r < 0)
                return r;

        r = qemu_config_section(config_file, "device", "balloon0",
                                "driver", "virtio-balloon",
                                "free-page-reporting", "on");
        if (r < 0)
                return r;

        if (ARCHITECTURE_SUPPORTS_VMGENID) {
                sd_id128_t vmgenid;
                r = sd_id128_get_invocation_app_specific(SD_ID128_MAKE(bd,84,6d,e3,e4,7d,4b,6c,a6,85,4a,87,0f,3c,a3,a0), &vmgenid);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get invocation ID, making up randomized vmgenid: %m");

                        r = sd_id128_randomize(&vmgenid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to make up randomized vmgenid: %m");
                }

                r = qemu_config_section(config_file, "device", "vmgenid0",
                                        "driver", "vmgenid");
                if (r < 0)
                        return r;

                r = qemu_config_keyf(config_file, "guid", SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(vmgenid));
                if (r < 0)
                        return r;
        }

        /* Start building the cmdline for items that must remain as command line arguments.
         * -S starts QEMU with vCPUs paused — we set up devices via QMP then resume with "cont". */
        cmdline = strv_new(qemu_binary,
                           "-S",
                           "-no-user-config");
        if (!cmdline)
                return log_oom();

        if (!sd_id128_is_null(arg_uuid))
                if (strv_extend_many(&cmdline, "-uuid", SD_ID128_TO_UUID_STRING(arg_uuid)) < 0)
                        return log_oom();

        _cleanup_close_ int delegate_userns_fd = -EBADF, tap_fd = -EBADF;
        _cleanup_free_ char *tap_name = NULL;
        struct ether_addr mac_vm = {};

        if (arg_network_stack == NETWORK_STACK_TAP) {
                if (have_effective_cap(CAP_NET_ADMIN) <= 0) {
                        /* Without CAP_NET_ADMIN we use nsresourced to create a TAP device.
                         * The TAP fd is passed to QEMU via QMP getfd + SCM_RIGHTS after
                         * the handshake, then referenced by name in netdev_add. */
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

                        config.network = (NetworkInfo) {
                                .type = "tap",
                                .fd   = TAKE_FD(tap_fd),
                        };
                } else {
                        /* With CAP_NET_ADMIN we create the TAP interface by name.
                         * Configure via QMP after QEMU starts. */
                        tap_name = strjoin("vt-", arg_machine);
                        if (!tap_name)
                                return log_oom();

                        (void) net_shorten_ifname(tap_name, /* check_naming_scheme= */ false);

                        if (ether_addr_is_null(&arg_network_provided_mac)) {
                                r = net_generate_mac(arg_machine, &mac_vm, VM_TAP_HASH_KEY, 0);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to generate predictable MAC address for VM side: %m");
                        } else
                                mac_vm = arg_network_provided_mac;

                        config.network = (NetworkInfo) {
                                .type    = "tap",
                                .ifname  = TAKE_PTR(tap_name),
                                .mac     = mac_vm,
                                .mac_set = true,
                                .fd      = -EBADF,
                        };
                }
        } else if (arg_network_stack == NETWORK_STACK_USER) {
                config.network = (NetworkInfo) {
                        .type = "user",
                        .fd   = -EBADF,
                };
        } else {
                r = strv_extend_many(&cmdline, "-nic", "none");
                if (r < 0)
                        return log_oom();
        }

        /* A shared memory backend might increase ram usage so only add one if actually necessary for virtiofsd. */
        if (arg_directory || arg_runtime_mounts.n_mounts != 0) {
                r = qemu_config_section(config_file, "object", "mem",
                                        "qom-type", "memory-backend-memfd",
                                        "size", mem,
                                        "share", "on");
                if (r < 0)
                        return r;
        }

        bool use_vsock = arg_vsock > 0;
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
                r = strv_extend(&cmdline, "--add-fd");
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&cmdline, "fd=%d,set=1,opaque=/dev/kvm", kvm_device_fd);
                if (r < 0)
                        return log_oom();

                if (!GREEDY_REALLOC(pass_fds, n_pass_fds + 1))
                        return log_oom();

                pass_fds[n_pass_fds++] = kvm_device_fd;

                r = qemu_config_section(config_file, "accel", /* id= */ NULL,
                                        "accel", "kvm",
                                        "device", "/dev/fdset/1");
                if (r < 0)
                        return r;
        } else {
                r = qemu_config_section(config_file, "accel", /* id= */ NULL,
                                        "accel", use_kvm ? "kvm" : "tcg");
                if (r < 0)
                        return r;
        }

        unsigned child_cid = arg_vsock_cid;
        if (use_vsock) {
                config.vsock.fd = TAKE_FD(vhost_device_fd);

                if (config.vsock.fd < 0) {
                        config.vsock.fd = open("/dev/vhost-vsock", O_RDWR|O_CLOEXEC);
                        if (config.vsock.fd < 0)
                                return log_error_errno(errno, "Failed to open /dev/vhost-vsock as read/write: %m");
                }

                r = vsock_fix_child_cid(config.vsock.fd, &child_cid, arg_machine);
                if (r < 0)
                        return log_error_errno(r, "Failed to fix CID for the guest VSOCK socket: %m");

                config.vsock.cid = child_cid;
        }

        /* -cpu stays on cmdline since not all flags are supported in config */
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

        case CONSOLE_NATIVE:
                /* Use a PTY instead of chardev stdio to prevent QEMU from setting O_NONBLOCK on
                 * our stdio file descriptions (see qemu's chardev/char-stdio.c and char-fd.c).
                 * Use PTY_FORWARD_DUMB_TERMINAL|PTY_FORWARD_TRANSPARENT so the forwarder just
                 * shovels bytes without any terminal manipulation or escape sequence handling. */
                ptyfwd_flags |= PTY_FORWARD_DUMB_TERMINAL|PTY_FORWARD_TRANSPARENT;

                _fallthrough_;

        case CONSOLE_READ_ONLY:
                if (arg_console_mode == CONSOLE_READ_ONLY)
                        ptyfwd_flags |= PTY_FORWARD_READ_ONLY;

                _fallthrough_;

        case CONSOLE_INTERACTIVE: {
                _cleanup_free_ char *pty_path = NULL;

                master = openpt_allocate(O_RDWR|O_NONBLOCK, &pty_path);
                if (master < 0)
                        return log_error_errno(master, "Failed to setup pty: %m");

                r = strv_extend_many(&cmdline, "-nographic", "-nodefaults");
                if (r < 0)
                        return log_oom();

                /* Enable mux for native console so the QEMU monitor is accessible via Ctrl-a c */
                r = qemu_config_section(config_file, "chardev", "console",
                                        "backend", "serial",
                                        "path", pty_path,
                                        "mux", on_off(arg_console_mode == CONSOLE_NATIVE));
                if (r < 0)
                        return r;

                if (arg_console_mode == CONSOLE_NATIVE) {
                        r = qemu_config_section(config_file, "mon", "mon0",
                                                "chardev", "console");
                        if (r < 0)
                                return r;
                }

                break;
        }

        case CONSOLE_GUI:
                /* -vga is a convenience option, keep on cmdline */
                r = strv_extend_many(&cmdline, "-vga", "virtio");
                if (r < 0)
                        return log_oom();

                r = qemu_config_section(config_file, "device", "virtio-serial0",
                                        "driver", "virtio-serial");
                if (r < 0)
                        return r;

                r = qemu_config_section(config_file, "chardev", "vdagent",
                                        "backend", "qemu-vdagent",
                                        "clipboard", "on",
                                        "debug", "0");
                if (r < 0)
                        return r;

                r = qemu_config_section(config_file, "device", "vdagent-port0",
                                        "driver", "virtserialport",
                                        "chardev", "vdagent",
                                        "name", "org.qemu.guest_agent.0");
                if (r < 0)
                        return r;

                /* Attach a USB xHCI controller and a USB keyboard. We prefer USB over the implicit PS/2
                 * keyboard so that EDK2's UsbKbDxe driver runs, which registers the default HII keyboard
                 * layout package — the PS/2 driver does not. That makes
                 * EFI_HII_DATABASE_PROTOCOL.GetKeyboardLayout() return a usable layout, which systemd-boot
                 * then exports via the LoaderKeyboardLayout EFI variable, which is useful for testing that
                 * codepath actually works. */
                r = qemu_config_section(config_file, "device", "xhci0",
                                        "driver", "qemu-xhci");
                if (r < 0)
                        return r;

                r = qemu_config_section(config_file, "device", "usb-kbd0",
                                        "driver", "usb-kbd",
                                        "bus", "xhci0.0");
                if (r < 0)
                        return r;

                break;

        case CONSOLE_HEADLESS:
                r = strv_extend_many(&cmdline, "-nographic", "-nodefaults");
                if (r < 0)
                        return log_oom();

                break;

        default:
                assert_not_reached();
        }

        if (!IN_SET(arg_console_mode, CONSOLE_GUI, CONSOLE_HEADLESS)) {
                if (arg_console_transport == CONSOLE_TRANSPORT_SERIAL) {
                        /* Use -serial to connect the chardev to the platform's default serial
                         * device (e.g. isa-serial on x86, PL011 on ARM). On some platforms the
                         * serial device is a sysbus device that can only be connected via
                         * serial_hd() which is populated by -serial, not via the config file. */
                        r = strv_extend_many(&cmdline, "-serial", "chardev:console");
                        if (r < 0)
                                return log_oom();
                } else {
                        r = qemu_config_section(config_file, "device", "vmspawn-virtio-serial-pci",
                                                "driver", "virtio-serial-pci");
                        if (r < 0)
                                return r;

                        r = qemu_config_section(config_file, "device", "virtconsole0",
                                                "driver", "virtconsole",
                                                "chardev", "console");
                        if (r < 0)
                                return r;
                }
        }

        _cleanup_(unlink_and_freep) char *ovmf_vars = NULL;
        r = cmdline_add_ovmf(config_file, ovmf_config, &ovmf_vars);
        if (r < 0)
                return r;

        if (arg_linux) {
                r = strv_extend_many(&cmdline, "-kernel", arg_linux);
                if (r < 0)
                        return log_oom();

                /* We can't rely on gpt-auto-generator when direct kernel booting so synthesize a root=
                 * kernel argument instead. */
                if (arg_linux_image_type != KERNEL_IMAGE_TYPE_UKI && arg_image) {
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

                if (arg_image_disk_type != DISK_TYPE_VIRTIO_SCSI_CDROM) {
                        r = grow_image(arg_image, arg_grow_image);
                        if (r < 0)
                                return r;
                /* CD-ROMs are read-only, so override any "rw" on the kernel command line. */
                } else if (strv_contains(arg_kernel_cmdline_extra, "rw") &&
                           strv_extend(&arg_kernel_cmdline_extra, "ro") < 0)
                        return log_oom();
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
                                return log_error_errno(r, "Failed to create ephemeral snapshot of '%s': %m", arg_directory);

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

                _cleanup_free_ char *id = strdup("rootdir"), *tag = strdup("root");
                if (!id || !tag)
                        return log_oom();

                if (!GREEDY_REALLOC(config.virtiofs.entries, config.virtiofs.n_entries + 1))
                        return log_oom();

                config.virtiofs.entries[config.virtiofs.n_entries++] = (VirtiofsInfo) {
                        .id          = TAKE_PTR(id),
                        .socket_path = TAKE_PTR(listen_address),
                        .tag         = TAKE_PTR(tag),
                };

                if (strv_extend(&arg_kernel_cmdline_extra, "root=root rootfstype=virtiofs rw") < 0)
                        return log_oom();
        }

        /* Extra drive validation is done in the post-fork drive info construction loop
         * to avoid stat()'ing each drive twice. */

        if (!IN_SET(arg_console_mode, CONSOLE_GUI, CONSOLE_HEADLESS)) {
                r = strv_prepend(&arg_kernel_cmdline_extra,
                                 arg_console_transport == CONSOLE_TRANSPORT_SERIAL ?
                                 "console=" QEMU_SERIAL_CONSOLE_NAME : "console=hvc0");
                if (r < 0)
                        return log_oom();

                /* Propagate the host's $TERM into the VM via the kernel command line. TERM= is
                 * picked up by PID 1 and inherited by services on /dev/console, and
                 * systemd.tty.term.hvc0= is used by services directly attached to /dev/hvc0 (such
                 * as serial-getty). While systemd can auto-detect the terminal type via DCS
                 * XTGETTCAP, not all terminal emulators implement this, so let's always propagate
                 * $TERM if we have it. */
                const char *term = getenv("TERM");
                if (term_env_valid(term)) {
                        FOREACH_STRING(tty_key, "systemd.tty.term.hvc0", "TERM") {
                                _cleanup_free_ char *p = strjoin(tty_key, "=", term);
                                if (!p)
                                        return log_oom();

                                if (strv_consume_prepend(&arg_kernel_cmdline_extra, TAKE_PTR(p)) < 0)
                                        return log_oom();
                        }
                }
        }

        _cleanup_free_ char *fstab_extra = NULL;

        for (size_t j = 0; j < arg_runtime_mounts.n_mounts; j++) {
                RuntimeMount *m = arg_runtime_mounts.mounts + j;
                _cleanup_free_ char *listen_address = NULL, *id = NULL, *tag = NULL;
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

                if (asprintf(&id, "mnt%zu", j) < 0)
                        return log_oom();

                tag = strdup(id);
                if (!tag)
                        return log_oom();

                /* fstab uses whitespace as field separator, so octal-escape spaces in paths */
                _cleanup_free_ char *escaped_target = octescape_full(m->target, SIZE_MAX, " \t");
                if (!escaped_target)
                        return log_oom();

                if (strextendf(&fstab_extra, "%s %s virtiofs %s,x-initrd.mount\n",
                               id, escaped_target, m->read_only ? "ro" : "rw") < 0)
                        return log_oom();

                if (!GREEDY_REALLOC(config.virtiofs.entries, config.virtiofs.n_entries + 1))
                        return log_oom();

                config.virtiofs.entries[config.virtiofs.n_entries++] = (VirtiofsInfo) {
                        .id          = TAKE_PTR(id),
                        .socket_path = TAKE_PTR(listen_address),
                        .tag         = TAKE_PTR(tag),
                };
        }

        if (fstab_extra) {
                /* If the user already specified a fstab.extra credential, combine it with ours */
                MachineCredential *existing = machine_credential_find(&arg_credentials, "fstab.extra");
                if (existing) {
                        _cleanup_free_ char *combined = NULL;

                        if (existing->size > 0 && existing->data[existing->size - 1] != '\n')
                                r = asprintf(&combined, "%.*s\n%s", (int) existing->size, existing->data, fstab_extra);
                        else
                                r = asprintf(&combined, "%.*s%s", (int) existing->size, existing->data, fstab_extra);
                        if (r < 0)
                                return log_oom();

                        erase_and_free(existing->data);
                        existing->data = TAKE_PTR(combined);
                        existing->size = r;
                } else {
                        r = machine_credential_add(&arg_credentials, "fstab.extra", fstab_extra, SIZE_MAX);
                        if (r < 0)
                                return r;
                }
        }

        _cleanup_(rm_rf_physical_and_freep) char *smbios_dir = NULL;
        _cleanup_close_ int smbios_dir_fd = mkdtemp_open("/var/tmp/vmspawn-smbios-XXXXXX", /* flags= */ 0, &smbios_dir);
        if (smbios_dir_fd < 0)
                return log_error_errno(smbios_dir_fd, "Failed to create temporary directory: %m");

        r = cmdline_add_smbios11(&cmdline, smbios_dir_fd, smbios_dir);
        if (r < 0)
                return r;

        /* disable TPM autodetection if the user's hardware doesn't support it */
        if (!ARCHITECTURE_SUPPORTS_TPM) {
                if (arg_tpm > 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "TPM not supported on %s, refusing", architecture_to_string(native_architecture()));
                if (arg_tpm < 0) {
                        arg_tpm = false;
                        log_debug("TPM not supported on %s, disabling tpm autodetection and continuing", architecture_to_string(native_architecture()));
                }
        }

        _cleanup_free_ char *swtpm = NULL;
        if (arg_tpm != 0) {
                if (arg_tpm_state_mode == STATE_AUTO && !arg_ephemeral) {
                        assert(!arg_tpm_state_path);

                        r = make_sidecar_path(".tpmstate", &arg_tpm_state_path);
                        if (r < 0)
                                return r;

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
                r = qemu_config_section(config_file, "chardev", "chrtpm",
                                        "backend", "socket",
                                        "path", tpm_socket_address);
                if (r < 0)
                        return r;

                r = qemu_config_section(config_file, "tpmdev", "tpm0",
                                        "type", "emulator",
                                        "chardev", "chrtpm");
                if (r < 0)
                        return r;

                const char *tpm_driver;
                if (native_architecture() == ARCHITECTURE_X86_64)
                        tpm_driver = "tpm-tis";
                else if (IN_SET(native_architecture(), ARCHITECTURE_ARM64, ARCHITECTURE_ARM64_BE))
                        tpm_driver = "tpm-tis-device";
                else
                        tpm_driver = NULL;

                if (tpm_driver) {
                        r = qemu_config_section(config_file, "device", "tpmdev0",
                                                "driver", tpm_driver,
                                                "tpmdev", "tpm0");
                        if (r < 0)
                                return r;
                }
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
                if (asprintf(&listen_address, "vsock:2:%u", child_cid) < 0)
                        return log_oom();

                if (!GREEDY_REALLOC(children, n_children + 1))
                        return log_oom();

                _cleanup_(fork_notify_terminate) PidRef child = PIDREF_NULL;
                r = fork_journal_remote(
                                listen_address,
                                arg_forward_journal,
                                arg_forward_journal_max_use,
                                arg_forward_journal_keep_free,
                                arg_forward_journal_max_file_size,
                                arg_forward_journal_max_files,
                                &child);
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

        if (use_vsock) {
                notify_sock_fd = open_vsock();
                if (notify_sock_fd < 0)
                        return log_error_errno(notify_sock_fd, "Failed to open VSOCK: %m");

                r = add_vsock_credential(notify_sock_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to add VSOCK credential: %m");
        }

        r = cmdline_add_credentials(&cmdline, smbios_dir_fd, smbios_dir);
        if (r < 0)
                return r;

        r = cmdline_add_kernel_cmdline(&cmdline, smbios_dir_fd, smbios_dir);
        if (r < 0)
                return r;

        _cleanup_close_pair_ int bridge_fds[2] = EBADF_PAIR;
        r = qemu_config_add_qmp_monitor(config_file, bridge_fds, &pass_fds, &n_pass_fds);
        if (r < 0)
                return r;

        /* Pre-allocate PCIe root ports for QMP device_add hotplug. On PCIe machine types
         * (q35, virt), QMP device_add is always hotplug — the root bus (pcie.0) does not support
         * it. Each root port provides one slot for hotplug. We create enough ports for all devices
         * that will be set up via QMP, plus VMSPAWN_PCIE_HOTPLUG_SPARES spare ports for future
         * runtime hotplug. */
        if (ARCHITECTURE_NEEDS_PCIE_ROOT_PORTS) {
                /* Count the PCI devices that assign_pcie_ports() will place on a builtin port:
                 * one per non-SCSI drive (root + extras + bind volumes; SCSI drives share a
                 * virtio-scsi-pci controller drawn from the hotplug pool, see
                 * assign_pcie_ports()), one if network is configured, one per virtiofs entry,
                 * one if vsock is in use. Plus a fixed pool of hotplug spares for runtime
                 * device_add. */
                size_t n_drive_ports = 0;
                if (!IN_SET(arg_image_disk_type, DISK_TYPE_VIRTIO_SCSI, DISK_TYPE_VIRTIO_SCSI_CDROM))
                        n_drive_ports++;
                FOREACH_ARRAY(d, arg_extra_drives.drives, arg_extra_drives.n_drives) {
                        DiskType dt = d->disk_type >= 0 ? d->disk_type : arg_image_disk_type;
                        if (!IN_SET(dt, DISK_TYPE_VIRTIO_SCSI, DISK_TYPE_VIRTIO_SCSI_CDROM))
                                n_drive_ports++;
                }
                FOREACH_ARRAY(bv, arg_bind_volumes.items, arg_bind_volumes.n_items) {
                        DiskType dt = disk_type_from_bind_volume_config((*bv)->config);
                        if (dt < 0)
                                continue; /* unreachable: parser rejects invalid configs */
                        if (!IN_SET(dt, DISK_TYPE_VIRTIO_SCSI, DISK_TYPE_VIRTIO_SCSI_CDROM))
                                n_drive_ports++;
                }

                size_t n_pcie_ports =
                        n_drive_ports +                                    /* non-SCSI drives */
                        (arg_network_stack != NETWORK_STACK_NONE ? 1 : 0) + /* network */
                        (arg_directory ? 1 : 0) +                          /* rootdir virtiofs */
                        arg_runtime_mounts.n_mounts +                      /* runtime virtiofs */
                        (use_vsock ? 1 : 0) +                              /* vsock */
                        VMSPAWN_PCIE_HOTPLUG_SPARES;                       /* hotplug pool */

                /* Guard the unsigned subtraction below against future refactors that might drop the
                 * fixed additions. */
                assert(n_pcie_ports >= VMSPAWN_PCIE_HOTPLUG_SPARES);

                /* Cap derived from the packing range: cannot exceed VMSPAWN_PCIE_PACK_MAX_PORTS
                 * (= 15 slots × 8 functions = 120) without running into the 0x1f LPC slot. */
                if (n_pcie_ports > VMSPAWN_PCIE_PACK_MAX_PORTS)
                        return log_error_errno(SYNTHETIC_ERRNO(E2BIG),
                                               "Too many PCIe root ports requested (%zu, max %u). "
                                               "Reduce the number of extra drives or runtime mounts.",
                                               n_pcie_ports, (unsigned) VMSPAWN_PCIE_PACK_MAX_PORTS);

                size_t n_builtin_ports = n_pcie_ports - VMSPAWN_PCIE_HOTPLUG_SPARES;
                for (size_t i = 0; i < n_pcie_ports; i++) {
                        char id[STRLEN("vmspawn-hotplug-pci-root-port-") + DECIMAL_STR_MAX(size_t)];
                        if (i < n_builtin_ports)
                                xsprintf(id, "vmspawn-pcieport-%zu", i);
                        else
                                xsprintf(id, "vmspawn-hotplug-pci-root-port-%zu", i - n_builtin_ports);

                        r = qemu_config_section(config_file, "device", id,
                                                "driver", "pcie-root-port");
                        if (r < 0)
                                return r;

                        /* chassis/slot are the PCIe-chassis identity (ACPI hotplug paths),
                         * independent of the PCI bus address below. */
                        r = qemu_config_keyf(config_file, "chassis", "%zu", i + 1);
                        if (r < 0)
                                return r;

                        r = qemu_config_keyf(config_file, "slot", "%zu", i + 1);
                        if (r < 0)
                                return r;

                        /* Pack 8 root ports per pcie.0 device-number as multifunction, so 14
                         * ports cost 2 slots on pcie.0 instead of 14. Each function remains
                         * independently hot-pluggable (QEMU docs/pcie.txt §5.1). */
                        size_t pci_slot = VMSPAWN_PCIE_PACK_BASE_SLOT + i / 8;
                        size_t pci_fn   = i % 8;
                        assert(pci_slot < VMSPAWN_PCIE_PACK_END_SLOT);
                        r = qemu_config_keyf(config_file, "addr", "0x%zx.%zu", pci_slot, pci_fn);
                        if (r < 0)
                                return r;
                        if (pci_fn == 0) {
                                r = qemu_config_key(config_file, "multifunction", "on");
                                if (r < 0)
                                        return r;
                        }
                }
        }

        /* Finalize the config file and add -readconfig to the cmdline */
        r = fflush_and_check(config_file);
        if (r < 0)
                return log_error_errno(r, "Failed to write QEMU config file: %m");
        config_file = safe_fclose(config_file);

        r = strv_extend_many(&cmdline, "-readconfig", config_path);
        if (r < 0)
                return log_oom();

        const char *e = secure_getenv("SYSTEMD_VMSPAWN_QEMU_EXTRA");
        if (e) {
                r = strv_split_and_extend_full(&cmdline, e,
                                               /* separators= */ NULL, /* filter_duplicates= */ false,
                                               EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse $SYSTEMD_VMSPAWN_QEMU_EXTRA: %m");
        }

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *config_contents = NULL;

                r = read_full_file(config_path, &config_contents, /* ret_size= */ NULL);
                if (r < 0)
                        log_debug_errno(r, "Failed to read back QEMU config file, ignoring: %m");
                else
                        log_debug("QEMU config file %s:\n%s", config_path, config_contents);

                _cleanup_free_ char *joined = quote_command_line(cmdline, SHELL_ESCAPE_EMPTY);
                if (!joined)
                        return log_oom();

                log_debug("Executing: %s", joined);
        }

        _cleanup_close_ int child_pty = -EBADF;
        if (master >= 0) {
                child_pty = pty_open_peer(master, O_RDWR|O_CLOEXEC|O_NOCTTY);
                if (child_pty < 0)
                        return log_error_errno(child_pty, "Failed to open PTY slave: %m");
        }

        /* SIGTERM, not SIGKILL — let QEMU flush state on error-path early exits. */
        _cleanup_(pidref_done_sigterm_wait) PidRef child_pidref = PIDREF_NULL;
        r = pidref_safe_fork_full(
                        qemu_binary,
                        child_pty >= 0 ? (const int[]) { child_pty, child_pty, child_pty } : NULL,
                        pass_fds, n_pass_fds,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_CLOEXEC_OFF|FORK_RLIMIT_NOFILE_SAFE|
                        (child_pty >= 0 ? FORK_REARRANGE_STDIO : 0),
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

        /* Close QEMU's end of the QMP socketpair in the parent. We don't need it anymore. */
        child_pty = safe_close(child_pty);
        bridge_fds[1] = safe_close(bridge_fds[1]);

        r = prepare_device_info(runtime_dir, &config);
        if (r < 0)
                return r;

        /* Connect to VMM backend */
        _cleanup_(vmspawn_qmp_bridge_freep) VmspawnQmpBridge *bridge = NULL;
        r = vmspawn_qmp_init(&bridge, bridge_fds[0], event);
        if (r < 0)
                return r;

        TAKE_FD(bridge_fds[0]);

        /* Probe QEMU feature availability synchronously before device setup consumes the flags. */
        r = vmspawn_qmp_probe_features(bridge);
        if (r < 0)
                return r;

        /* Device setup — all before resuming vCPUs */
        r = vmspawn_qmp_setup_drives(bridge, &config.drives);
        if (r < 0)
                return r;

        if (config.network.type) {
                r = vmspawn_qmp_setup_network(bridge, &config.network);
                if (r < 0)
                        return r;
        }

        r = vmspawn_qmp_setup_virtiofs(bridge, &config.virtiofs);
        if (r < 0)
                return r;

        r = vmspawn_qmp_setup_vsock(bridge, &config.vsock);
        if (r < 0)
                return r;

        /* Resume vCPUs and switch to async event processing */
        r = vmspawn_qmp_start(bridge);
        if (r < 0)
                return r;

        /* Varlink server for VM control */
        _cleanup_(vmspawn_varlink_context_freep) VmspawnVarlinkContext *varlink_ctx = NULL;
        _cleanup_free_ char *control_address = NULL;
        r = vmspawn_varlink_setup(&varlink_ctx, bridge, runtime_dir, &control_address);
        if (r < 0)
                return r;

        TAKE_PTR(bridge);

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
        if (!arg_keep_unit && (arg_register == 0 || arg_runtime_scope != RUNTIME_SCOPE_SYSTEM)) {
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

        MachineRegistrationContext machine_ctx = {
                .scope      = arg_runtime_scope == RUNTIME_SCOPE_SYSTEM ? RUNTIME_SCOPE_SYSTEM : _RUNTIME_SCOPE_INVALID,
                .system_bus = system_bus,
                .user_bus   = runtime_bus,
        };
        if (arg_register != 0) {
                char vm_address[STRLEN("vsock/") + DECIMAL_STR_MAX(unsigned)];
                xsprintf(vm_address, "vsock/%u", child_cid);

                const MachineRegistration reg = {
                        .name                 = arg_machine,
                        .id                   = arg_uuid,
                        .service              = "systemd-vmspawn",
                        .class                = "vm",
                        .pidref               = &child_pidref,
                        .root_directory       = arg_directory,
                        .vsock_cid            = child_cid,
                        .ssh_address          = child_cid != VMADDR_CID_ANY ? vm_address : NULL,
                        .ssh_private_key_path = ssh_private_key_path,
                        .control_address      = control_address,
                        .allocate_unit        = !arg_keep_unit,
                };

                r = register_machine_with_fallback_and_log(
                                &machine_ctx,
                                &reg,
                                /* graceful= */ arg_register < 0);
                if (r < 0)
                        return r;
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
                r = pty_forward_new(event, master, ptyfwd_flags, &forward);
                if (r < 0)
                        return log_error_errno(r, "Failed to create PTY forwarder: %m");

                if (!FLAGS_SET(ptyfwd_flags, PTY_FORWARD_DUMB_TERMINAL)) {
                        if (!terminal_is_dumb()) {
                                r = osc_context_open_vm(arg_machine, /* ret_seq= */ NULL, &osc_context_id);
                                if (r < 0)
                                        return r;
                        }

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
        }

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        /* Kill if it is not dead yet anyway */
        if (scope_allocated)
                terminate_scope(runtime_bus, arg_machine);

        unregister_machine_with_fallback_and_log(&machine_ctx, arg_machine);

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

static int determine_kernel(void) {
        int r;

        if (!arg_linux && arg_directory) {
                /* A kernel is required for directory type images so attempt to find one under /boot and /efi */
                r = discover_boot_entry(arg_directory, &arg_linux, &arg_initrds);
                if (r < 0)
                        return log_error_errno(r, "Failed to locate UKI in directory type image, please specify one with --linux=.");

                log_debug("Discovered UKI image at %s", arg_linux);
        }

        if (!arg_linux) {
                if (arg_firmware_type == _FIRMWARE_INVALID)
                        arg_firmware_type = FIRMWARE_UEFI;
                return 0;
        }

        r = inspect_kernel(AT_FDCWD, arg_linux, &arg_linux_image_type);
        if (r < 0)
                return log_error_errno(r, "Failed to determine '%s' kernel image type: %m", arg_linux);

        if (arg_linux_image_type == KERNEL_IMAGE_TYPE_UNKNOWN) {
                if (arg_firmware_type == FIRMWARE_UEFI)
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(EINVAL),
                                        "Kernel image '%s' is not a PE binary, --firmware=uefi (or a firmware path) is not supported.",
                                        arg_linux);
                if (arg_firmware_type == _FIRMWARE_INVALID)
                        arg_firmware_type = FIRMWARE_NONE;
        }

        if (arg_firmware_type == _FIRMWARE_INVALID)
                arg_firmware_type = FIRMWARE_UEFI;

        return 0;
}

static int verify_arguments(void) {
        if (!strv_isempty(arg_initrds) && !arg_linux)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Option --initrd= cannot be used without --linux=.");

        if (arg_firmware_type != FIRMWARE_UEFI && arg_linux_image_type == KERNEL_IMAGE_TYPE_UKI)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Booting a UKI requires --firmware=uefi.");

        if (arg_firmware_type == FIRMWARE_NONE && !arg_linux)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--firmware=none requires --linux= to be specified.");

        if (arg_image_disk_type == DISK_TYPE_VIRTIO_SCSI_CDROM) {
                if (arg_ephemeral)
                        log_warning("--ephemeral has no effect with --image-disk-type=scsi-cd (CD-ROMs are read-only).");
                if (arg_discard_disk)
                        log_warning("--discard-disk has no effect with --image-disk-type=scsi-cd (CD-ROMs are read-only).");
                if (arg_grow_image)
                        log_warning("--grow-image has no effect with --image-disk-type=scsi-cd (CD-ROMs are read-only).");
        }

        if (arg_grow_image && arg_image_format == IMAGE_FORMAT_QCOW2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--grow-image is not supported for qcow2 images, use 'qemu-img resize FILE SIZE'.");

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

        if (arg_firmware_describe) {
                _cleanup_(ovmf_config_freep) OvmfConfig *ovmf_config = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;

                r = find_ovmf_config(arg_firmware_features_include, arg_firmware_features_exclude, &ovmf_config, &json);
                if (r < 0)
                        return log_error_errno(r, "Failed to find OVMF config: %m");

                r = sd_json_variant_dump(json, SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_COLOR_AUTO, stdout, /* prefix= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to output JSON: %m");

                return 0;
        }

        r = determine_names();
        if (r < 0)
                return r;

        r = determine_kernel();
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
