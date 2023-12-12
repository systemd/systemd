/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_BLKID
#endif
#include <errno.h>
#include <getopt.h>
#include <linux/fs.h>
#include <linux/loop.h>
#if HAVE_SELINUX
#include <selinux/selinux.h>
#endif
#include <stdlib.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "ether-addr-util.h"
#include "barrier.h"
#include "base-filesystem.h"
#include "blkid-util.h"
#include "btrfs-util.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "cap-list.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "chase.h"
#include "common-signal.h"
#include "copy.h"
#include "cpu-set-util.h"
#include "creds-util.h"
#include "dev-setup.h"
#include "discover-image.h"
#include "dissect-image.h"
#include "env-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "gpt.h"
#include "hexdecoct.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "io-util.h"
#include "log.h"
#include "loop-util.h"
#include "loopback-setup.h"
#include "machine-credential.h"
#include "macro.h"
#include "main-func.h"
#include "missing_sched.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "netlink-util.h"
#include "nspawn-bind-user.h"
#include "nspawn-cgroup.h"
#include "nspawn-def.h"
#include "nspawn-expose-ports.h"
#include "nspawn-mount.h"
#include "nspawn-network.h"
#include "nspawn-oci.h"
#include "nspawn-patch-uid.h"
#include "nspawn-register.h"
#include "nspawn-seccomp.h"
#include "nspawn-settings.h"
#include "nspawn-setuid.h"
#include "nspawn-stub-pid1.h"
#include "nspawn-util.h"
#include "nspawn.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "ptyfwd.h"
#include "random-util.h"
#include "raw-clone.h"
#include "resolve-util.h"
#include "rlimit-util.h"
#include "rm-rf.h"
#include "seccomp-util.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "sysctl-util.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "unit-name.h"
#include "user-util.h"

/* The notify socket inside the container it can use to talk to nspawn using the sd_notify(3) protocol */
#define NSPAWN_NOTIFY_SOCKET_PATH "/run/host/notify"
#define NSPAWN_MOUNT_TUNNEL "/run/host/incoming"

#define EXIT_FORCE_RESTART 133

typedef enum ContainerStatus {
        CONTAINER_TERMINATED,
        CONTAINER_REBOOTED,
} ContainerStatus;

static char *arg_directory = NULL;
static char *arg_template = NULL;
static char *arg_chdir = NULL;
static char *arg_pivot_root_new = NULL;
static char *arg_pivot_root_old = NULL;
static char *arg_user = NULL;
static uid_t arg_uid = UID_INVALID;
static gid_t arg_gid = GID_INVALID;
static gid_t* arg_supplementary_gids = NULL;
static size_t arg_n_supplementary_gids = 0;
static sd_id128_t arg_uuid = {};
static char *arg_machine = NULL;     /* The name used by the host to refer to this */
static char *arg_hostname = NULL;    /* The name the payload sees by default */
static const char *arg_selinux_context = NULL;
static const char *arg_selinux_apifs_context = NULL;
static char *arg_slice = NULL;
static bool arg_private_network = false;
static bool arg_read_only = false;
static StartMode arg_start_mode = START_PID1;
static bool arg_ephemeral = false;
static LinkJournal arg_link_journal = LINK_AUTO;
static bool arg_link_journal_try = false;
static uint64_t arg_caps_retain =
        (1ULL << CAP_AUDIT_CONTROL) |
        (1ULL << CAP_AUDIT_WRITE) |
        (1ULL << CAP_CHOWN) |
        (1ULL << CAP_DAC_OVERRIDE) |
        (1ULL << CAP_DAC_READ_SEARCH) |
        (1ULL << CAP_FOWNER) |
        (1ULL << CAP_FSETID) |
        (1ULL << CAP_IPC_OWNER) |
        (1ULL << CAP_KILL) |
        (1ULL << CAP_LEASE) |
        (1ULL << CAP_LINUX_IMMUTABLE) |
        (1ULL << CAP_MKNOD) |
        (1ULL << CAP_NET_BIND_SERVICE) |
        (1ULL << CAP_NET_BROADCAST) |
        (1ULL << CAP_NET_RAW) |
        (1ULL << CAP_SETFCAP) |
        (1ULL << CAP_SETGID) |
        (1ULL << CAP_SETPCAP) |
        (1ULL << CAP_SETUID) |
        (1ULL << CAP_SYS_ADMIN) |
        (1ULL << CAP_SYS_BOOT) |
        (1ULL << CAP_SYS_CHROOT) |
        (1ULL << CAP_SYS_NICE) |
        (1ULL << CAP_SYS_PTRACE) |
        (1ULL << CAP_SYS_RESOURCE) |
        (1ULL << CAP_SYS_TTY_CONFIG);
static uint64_t arg_caps_ambient = 0;
static CapabilityQuintet arg_full_capabilities = CAPABILITY_QUINTET_NULL;
static CustomMount *arg_custom_mounts = NULL;
static size_t arg_n_custom_mounts = 0;
static char **arg_setenv = NULL;
static bool arg_quiet = false;
static bool arg_register = true;
static bool arg_keep_unit = false;
static char **arg_network_interfaces = NULL;
static char **arg_network_macvlan = NULL;
static char **arg_network_ipvlan = NULL;
static bool arg_network_veth = false;
static char **arg_network_veth_extra = NULL;
static char *arg_network_bridge = NULL;
static char *arg_network_zone = NULL;
static char *arg_network_namespace_path = NULL;
struct ether_addr arg_network_provided_mac = {};
static PagerFlags arg_pager_flags = 0;
static unsigned long arg_personality = PERSONALITY_INVALID;
static char *arg_image = NULL;
static char *arg_oci_bundle = NULL;
static VolatileMode arg_volatile_mode = VOLATILE_NO;
static ExposePort *arg_expose_ports = NULL;
static char **arg_property = NULL;
static sd_bus_message *arg_property_message = NULL;
static UserNamespaceMode arg_userns_mode = USER_NAMESPACE_NO;
static uid_t arg_uid_shift = UID_INVALID, arg_uid_range = 0x10000U;
static UserNamespaceOwnership arg_userns_ownership = _USER_NAMESPACE_OWNERSHIP_INVALID;
static int arg_kill_signal = 0;
static CGroupUnified arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_UNKNOWN;
static SettingsMask arg_settings_mask = 0;
static int arg_settings_trusted = -1;
static char **arg_parameters = NULL;
static const char *arg_container_service_name = "systemd-nspawn";
static bool arg_notify_ready = false;
static bool arg_use_cgns = true;
static unsigned long arg_clone_ns_flags = CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWUTS;
static MountSettingsMask arg_mount_settings = MOUNT_APPLY_APIVFS_RO|MOUNT_APPLY_TMPFS_TMP;
static VeritySettings arg_verity_settings = VERITY_SETTINGS_DEFAULT;
static char **arg_syscall_allow_list = NULL;
static char **arg_syscall_deny_list = NULL;
#if HAVE_SECCOMP
static scmp_filter_ctx arg_seccomp = NULL;
#endif
static struct rlimit *arg_rlimit[_RLIMIT_MAX] = {};
static bool arg_no_new_privileges = false;
static int arg_oom_score_adjust = 0;
static bool arg_oom_score_adjust_set = false;
static CPUSet arg_cpu_set = {};
static ResolvConfMode arg_resolv_conf = RESOLV_CONF_AUTO;
static TimezoneMode arg_timezone = TIMEZONE_AUTO;
static unsigned arg_console_width = UINT_MAX, arg_console_height = UINT_MAX;
static DeviceNode* arg_extra_nodes = NULL;
static size_t arg_n_extra_nodes = 0;
static char **arg_sysctl = NULL;
static ConsoleMode arg_console_mode = _CONSOLE_MODE_INVALID;
static MachineCredentialContext arg_credentials = {};
static char **arg_bind_user = NULL;
static bool arg_suppress_sync = false;
static char *arg_settings_filename = NULL;
static Architecture arg_architecture = _ARCHITECTURE_INVALID;
static ImagePolicy *arg_image_policy = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_directory, freep);
STATIC_DESTRUCTOR_REGISTER(arg_template, freep);
STATIC_DESTRUCTOR_REGISTER(arg_chdir, freep);
STATIC_DESTRUCTOR_REGISTER(arg_pivot_root_new, freep);
STATIC_DESTRUCTOR_REGISTER(arg_pivot_root_old, freep);
STATIC_DESTRUCTOR_REGISTER(arg_user, freep);
STATIC_DESTRUCTOR_REGISTER(arg_supplementary_gids, freep);
STATIC_DESTRUCTOR_REGISTER(arg_machine, freep);
STATIC_DESTRUCTOR_REGISTER(arg_hostname, freep);
STATIC_DESTRUCTOR_REGISTER(arg_slice, freep);
STATIC_DESTRUCTOR_REGISTER(arg_setenv, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_network_interfaces, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_network_macvlan, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_network_ipvlan, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_network_veth_extra, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_network_bridge, freep);
STATIC_DESTRUCTOR_REGISTER(arg_network_zone, freep);
STATIC_DESTRUCTOR_REGISTER(arg_network_namespace_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_oci_bundle, freep);
STATIC_DESTRUCTOR_REGISTER(arg_property, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_property_message, sd_bus_message_unrefp);
STATIC_DESTRUCTOR_REGISTER(arg_parameters, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_verity_settings, verity_settings_done);
STATIC_DESTRUCTOR_REGISTER(arg_syscall_allow_list, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_syscall_deny_list, strv_freep);
#if HAVE_SECCOMP
STATIC_DESTRUCTOR_REGISTER(arg_seccomp, seccomp_releasep);
#endif
STATIC_DESTRUCTOR_REGISTER(arg_credentials, machine_credential_context_done);
STATIC_DESTRUCTOR_REGISTER(arg_cpu_set, cpu_set_reset);
STATIC_DESTRUCTOR_REGISTER(arg_sysctl, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_bind_user, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_settings_filename, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);

static int handle_arg_console(const char *arg) {
        if (streq(arg, "help")) {
                puts("autopipe\n"
                     "interactive\n"
                     "passive\n"
                     "pipe\n"
                     "read-only");
                return 0;
        }

        if (streq(arg, "interactive"))
                arg_console_mode = CONSOLE_INTERACTIVE;
        else if (streq(arg, "read-only"))
                arg_console_mode = CONSOLE_READ_ONLY;
        else if (streq(arg, "passive"))
                arg_console_mode = CONSOLE_PASSIVE;
        else if (streq(arg, "pipe")) {
                if (isatty(STDIN_FILENO) > 0 && isatty(STDOUT_FILENO) > 0)
                        log_full(arg_quiet ? LOG_DEBUG : LOG_NOTICE,
                                 "Console mode 'pipe' selected, but standard input/output are connected to an interactive TTY. "
                                 "Most likely you want to use 'interactive' console mode for proper interactivity and shell job control. "
                                 "Proceeding anyway.");

                arg_console_mode = CONSOLE_PIPE;
        } else if (streq(arg, "autopipe")) {
                if (isatty(STDIN_FILENO) > 0 && isatty(STDOUT_FILENO) > 0)
                        arg_console_mode = CONSOLE_INTERACTIVE;
                else
                        arg_console_mode = CONSOLE_PIPE;
        } else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown console mode: %s", optarg);

        arg_settings_mask |= SETTING_CONSOLE_MODE;
        return 1;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("systemd-nspawn", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] [PATH] [ARGUMENTS...]\n\n"
               "%5$sSpawn a command or OS in a light-weight container.%6$s\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Print version string\n"
               "  -q --quiet                Do not show status information\n"
               "     --no-pager             Do not pipe output into a pager\n"
               "     --settings=BOOLEAN     Load additional settings from .nspawn file\n\n"
               "%3$sImage:%4$s\n"
               "  -D --directory=PATH       Root directory for the container\n"
               "     --template=PATH        Initialize root directory from template directory,\n"
               "                            if missing\n"
               "  -x --ephemeral            Run container with snapshot of root directory, and\n"
               "                            remove it after exit\n"
               "  -i --image=PATH           Root file system disk image (or device node) for\n"
               "                            the container\n"
               "     --image-policy=POLICY  Specify disk image dissection policy\n"
               "     --oci-bundle=PATH      OCI bundle directory\n"
               "     --read-only            Mount the root directory read-only\n"
               "     --volatile[=MODE]      Run the system in volatile mode\n"
               "     --root-hash=HASH       Specify verity root hash for root disk image\n"
               "     --root-hash-sig=SIG    Specify pkcs7 signature of root hash for verity\n"
               "                            as a DER encoded PKCS7, either as a path to a file\n"
               "                            or as an ASCII base64 encoded string prefixed by\n"
               "                            'base64:'\n"
               "     --verity-data=PATH     Specify hash device for verity\n"
               "     --pivot-root=PATH[:PATH]\n"
               "                            Pivot root to given directory in the container\n\n"
               "%3$sExecution:%4$s\n"
               "  -a --as-pid2              Maintain a stub init as PID1, invoke binary as PID2\n"
               "  -b --boot                 Boot up full system (i.e. invoke init)\n"
               "     --chdir=PATH           Set working directory in the container\n"
               "  -E --setenv=NAME[=VALUE]  Pass an environment variable to PID 1\n"
               "  -u --user=USER            Run the command under specified user or UID\n"
               "     --kill-signal=SIGNAL   Select signal to use for shutting down PID 1\n"
               "     --notify-ready=BOOLEAN Receive notifications from the child init process\n"
               "     --suppress-sync=BOOLEAN\n"
               "                            Suppress any form of disk data synchronization\n\n"
               "%3$sSystem Identity:%4$s\n"
               "  -M --machine=NAME         Set the machine name for the container\n"
               "     --hostname=NAME        Override the hostname for the container\n"
               "     --uuid=UUID            Set a specific machine UUID for the container\n\n"
               "%3$sProperties:%4$s\n"
               "  -S --slice=SLICE          Place the container in the specified slice\n"
               "     --property=NAME=VALUE  Set scope unit property\n"
               "     --register=BOOLEAN     Register container as machine\n"
               "     --keep-unit            Do not register a scope for the machine, reuse\n"
               "                            the service unit nspawn is running in\n\n"
               "%3$sUser Namespacing:%4$s\n"
               "     --private-users=no     Run without user namespacing\n"
               "     --private-users=yes|pick|identity\n"
               "                            Run within user namespace, autoselect UID/GID range\n"
               "     --private-users=UIDBASE[:NUIDS]\n"
               "                            Similar, but with user configured UID/GID range\n"
               "     --private-users-ownership=MODE\n"
               "                            Adjust ('chown') or map ('map') OS tree ownership\n"
               "                            to private UID/GID range\n"
               "  -U                        Equivalent to --private-users=pick and\n"
               "                            --private-users-ownership=auto\n\n"
               "%3$sNetworking:%4$s\n"
               "     --private-network      Disable network in container\n"
               "     --network-interface=HOSTIF[:CONTAINERIF]\n"
               "                            Assign an existing network interface to the\n"
               "                            container\n"
               "     --network-macvlan=HOSTIF[:CONTAINERIF]\n"
               "                            Create a macvlan network interface based on an\n"
               "                            existing network interface to the container\n"
               "     --network-ipvlan=HOSTIF[:CONTAINERIF]\n"
               "                            Create an ipvlan network interface based on an\n"
               "                            existing network interface to the container\n"
               "  -n --network-veth         Add a virtual Ethernet connection between host\n"
               "                            and container\n"
               "     --network-veth-extra=HOSTIF[:CONTAINERIF]\n"
               "                            Add an additional virtual Ethernet link between\n"
               "                            host and container\n"
               "     --network-bridge=INTERFACE\n"
               "                            Add a virtual Ethernet connection to the container\n"
               "                            and attach it to an existing bridge on the host\n"
               "     --network-zone=NAME    Similar, but attach the new interface to an\n"
               "                            an automatically managed bridge interface\n"
               "     --network-namespace-path=PATH\n"
               "                            Set network namespace to the one represented by\n"
               "                            the specified kernel namespace file node\n"
               "  -p --port=[PROTOCOL:]HOSTPORT[:CONTAINERPORT]\n"
               "                            Expose a container IP port on the host\n\n"
               "%3$sSecurity:%4$s\n"
               "     --capability=CAP       In addition to the default, retain specified\n"
               "                            capability\n"
               "     --drop-capability=CAP  Drop the specified capability from the default set\n"
               "     --ambient-capability=CAP\n"
               "                            Sets the specified capability for the started\n"
               "                            process. Not useful if booting a machine.\n"
               "     --no-new-privileges    Set PR_SET_NO_NEW_PRIVS flag for container payload\n"
               "     --system-call-filter=LIST|~LIST\n"
               "                            Permit/prohibit specific system calls\n"
               "  -Z --selinux-context=SECLABEL\n"
               "                            Set the SELinux security context to be used by\n"
               "                            processes in the container\n"
               "  -L --selinux-apifs-context=SECLABEL\n"
               "                            Set the SELinux security context to be used by\n"
               "                            API/tmpfs file systems in the container\n\n"
               "%3$sResources:%4$s\n"
               "     --rlimit=NAME=LIMIT    Set a resource limit for the payload\n"
               "     --oom-score-adjust=VALUE\n"
               "                            Adjust the OOM score value for the payload\n"
               "     --cpu-affinity=CPUS    Adjust the CPU affinity of the container\n"
               "     --personality=ARCH     Pick personality for this container\n\n"
               "%3$sIntegration:%4$s\n"
               "     --resolv-conf=MODE     Select mode of /etc/resolv.conf initialization\n"
               "     --timezone=MODE        Select mode of /etc/localtime initialization\n"
               "     --link-journal=MODE    Link up guest journal, one of no, auto, guest, \n"
               "                            host, try-guest, try-host\n"
               "  -j                        Equivalent to --link-journal=try-guest\n\n"
               "%3$sMounts:%4$s\n"
               "     --bind=PATH[:PATH[:OPTIONS]]\n"
               "                            Bind mount a file or directory from the host into\n"
               "                            the container\n"
               "     --bind-ro=PATH[:PATH[:OPTIONS]\n"
               "                            Similar, but creates a read-only bind mount\n"
               "     --inaccessible=PATH    Over-mount file node with inaccessible node to mask\n"
               "                            it\n"
               "     --tmpfs=PATH:[OPTIONS] Mount an empty tmpfs to the specified directory\n"
               "     --overlay=PATH[:PATH...]:PATH\n"
               "                            Create an overlay mount from the host to \n"
               "                            the container\n"
               "     --overlay-ro=PATH[:PATH...]:PATH\n"
               "                            Similar, but creates a read-only overlay mount\n"
               "     --bind-user=NAME       Bind user from host to container\n\n"
               "%3$sInput/Output:%4$s\n"
               "     --console=MODE         Select how stdin/stdout/stderr and /dev/console are\n"
               "                            set up for the container.\n"
               "  -P --pipe                 Equivalent to --console=pipe\n\n"
               "%3$sCredentials:%4$s\n"
               "     --set-credential=ID:VALUE\n"
               "                            Pass a credential with literal value to container.\n"
               "     --load-credential=ID:PATH\n"
               "                            Load credential to pass to container from file or\n"
               "                            AF_UNIX stream socket.\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int custom_mount_check_all(void) {
        size_t i;

        for (i = 0; i < arg_n_custom_mounts; i++) {
                CustomMount *m = &arg_custom_mounts[i];

                if (path_equal(m->destination, "/") && arg_userns_mode != USER_NAMESPACE_NO) {
                        if (arg_userns_ownership != USER_NAMESPACE_OWNERSHIP_OFF)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--private-users-ownership=own may not be combined with custom root mounts.");
                        if (arg_uid_shift == UID_INVALID)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--private-users with automatic UID shift may not be combined with custom root mounts.");
                }
        }

        return 0;
}

static int detect_unified_cgroup_hierarchy_from_environment(void) {
        const char *e, *var = "SYSTEMD_NSPAWN_UNIFIED_HIERARCHY";
        int r;

        /* Allow the user to control whether the unified hierarchy is used */

        e = getenv(var);
        if (!e) {
                /* $UNIFIED_CGROUP_HIERARCHY has been renamed to $SYSTEMD_NSPAWN_UNIFIED_HIERARCHY. */
                var = "UNIFIED_CGROUP_HIERARCHY";
                e = getenv(var);
        }

        if (!isempty(e)) {
                r = parse_boolean(e);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse $%s: %m", var);
                if (r > 0)
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_ALL;
                else
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_NONE;
        }

        return 0;
}

static int detect_unified_cgroup_hierarchy_from_image(const char *directory) {
        int r;

        /* Let's inherit the mode to use from the host system, but let's take into consideration what systemd
         * in the image actually supports. */
        r = cg_all_unified();
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether we are in all unified mode.");
        if (r > 0) {
                /* Unified cgroup hierarchy support was added in 230. Unfortunately the detection
                 * routine only detects 231, so we'll have a false negative here for 230. */
                r = systemd_installation_has_version(directory, "230");
                if (r < 0)
                        return log_error_errno(r, "Failed to determine systemd version in container: %m");
                if (r > 0)
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_ALL;
                else
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_NONE;
        } else if (cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER) > 0) {
                /* Mixed cgroup hierarchy support was added in 233 */
                r = systemd_installation_has_version(directory, "233");
                if (r < 0)
                        return log_error_errno(r, "Failed to determine systemd version in container: %m");
                if (r > 0)
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_SYSTEMD;
                else
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_NONE;
        } else
                arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_NONE;

        log_debug("Using %s hierarchy for container.",
                  arg_unified_cgroup_hierarchy == CGROUP_UNIFIED_NONE ? "legacy" :
                  arg_unified_cgroup_hierarchy == CGROUP_UNIFIED_SYSTEMD ? "hybrid" : "unified");

        return 0;
}

static int parse_capability_spec(const char *spec, uint64_t *ret_mask) {
        uint64_t mask = 0;
        int r;

        for (;;) {
                _cleanup_free_ char *t = NULL;

                r = extract_first_word(&spec, &t, ",", 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse capability %s.", t);
                if (r == 0)
                        break;

                if (streq(t, "help")) {
                        for (int i = 0; i < capability_list_length(); i++) {
                                const char *name;

                                name = capability_to_name(i);
                                if (name)
                                        puts(name);
                        }

                        return 0; /* quit */
                }

                if (streq(t, "all"))
                        mask = UINT64_MAX;
                else {
                        r = capability_from_name(t);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse capability %s.", t);

                        mask |= 1ULL << r;
                }
        }

        *ret_mask = mask;
        return 1; /* continue */
}

static int parse_share_ns_env(const char *name, unsigned long ns_flag) {
        int r;

        r = getenv_bool(name);
        if (r == -ENXIO)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to parse $%s: %m", name);

        arg_clone_ns_flags = (arg_clone_ns_flags & ~ns_flag) | (r > 0 ? 0 : ns_flag);
        arg_settings_mask |= SETTING_CLONE_NS_FLAGS;
        return 0;
}

static int parse_mount_settings_env(void) {
        const char *e;
        int r;

        r = getenv_bool("SYSTEMD_NSPAWN_TMPFS_TMP");
        if (r < 0 && r != -ENXIO)
                return log_error_errno(r, "Failed to parse $SYSTEMD_NSPAWN_TMPFS_TMP: %m");
        if (r >= 0)
                SET_FLAG(arg_mount_settings, MOUNT_APPLY_TMPFS_TMP, r > 0);

        e = getenv("SYSTEMD_NSPAWN_API_VFS_WRITABLE");
        if (streq_ptr(e, "network"))
                arg_mount_settings |= MOUNT_APPLY_APIVFS_RO|MOUNT_APPLY_APIVFS_NETNS;

        else if (e) {
                r = parse_boolean(e);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse $SYSTEMD_NSPAWN_API_VFS_WRITABLE: %m");

                SET_FLAG(arg_mount_settings, MOUNT_APPLY_APIVFS_RO, r == 0);
                SET_FLAG(arg_mount_settings, MOUNT_APPLY_APIVFS_NETNS, false);
        }

        return 0;
}

static int parse_environment(void) {
        const char *e;
        int r;

        r = parse_share_ns_env("SYSTEMD_NSPAWN_SHARE_NS_IPC", CLONE_NEWIPC);
        if (r < 0)
                return r;
        r = parse_share_ns_env("SYSTEMD_NSPAWN_SHARE_NS_PID", CLONE_NEWPID);
        if (r < 0)
                return r;
        r = parse_share_ns_env("SYSTEMD_NSPAWN_SHARE_NS_UTS", CLONE_NEWUTS);
        if (r < 0)
                return r;
        r = parse_share_ns_env("SYSTEMD_NSPAWN_SHARE_SYSTEM", CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWUTS);
        if (r < 0)
                return r;

        r = parse_mount_settings_env();
        if (r < 0)
                return r;

        /* SYSTEMD_NSPAWN_USE_CGNS=0 can be used to disable CLONE_NEWCGROUP use,
         * even if it is supported. If not supported, it has no effect. */
        if (!cg_ns_supported())
                arg_use_cgns = false;
        else {
                r = getenv_bool("SYSTEMD_NSPAWN_USE_CGNS");
                if (r < 0) {
                        if (r != -ENXIO)
                                return log_error_errno(r, "Failed to parse $SYSTEMD_NSPAWN_USE_CGNS: %m");

                        arg_use_cgns = true;
                } else {
                        arg_use_cgns = r > 0;
                        arg_settings_mask |= SETTING_USE_CGNS;
                }
        }

        e = getenv("SYSTEMD_NSPAWN_CONTAINER_SERVICE");
        if (e)
                arg_container_service_name = e;

        e = getenv("SYSTEMD_NSPAWN_NETWORK_MAC");
        if (e) {
                r = parse_ether_addr(e, &arg_network_provided_mac);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse provided MAC address via environment variable");
        }

        r = getenv_bool("SYSTEMD_SUPPRESS_SYNC");
        if (r >= 0)
                arg_suppress_sync = r;
        else if (r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_SUPPRESS_SYNC, ignoring: %m");

        return detect_unified_cgroup_hierarchy_from_environment();
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_PRIVATE_NETWORK,
                ARG_UUID,
                ARG_READ_ONLY,
                ARG_CAPABILITY,
                ARG_AMBIENT_CAPABILITY,
                ARG_DROP_CAPABILITY,
                ARG_LINK_JOURNAL,
                ARG_BIND,
                ARG_BIND_RO,
                ARG_TMPFS,
                ARG_OVERLAY,
                ARG_OVERLAY_RO,
                ARG_INACCESSIBLE,
                ARG_SHARE_SYSTEM,
                ARG_REGISTER,
                ARG_KEEP_UNIT,
                ARG_NETWORK_INTERFACE,
                ARG_NETWORK_MACVLAN,
                ARG_NETWORK_IPVLAN,
                ARG_NETWORK_BRIDGE,
                ARG_NETWORK_ZONE,
                ARG_NETWORK_VETH_EXTRA,
                ARG_NETWORK_NAMESPACE_PATH,
                ARG_PERSONALITY,
                ARG_VOLATILE,
                ARG_TEMPLATE,
                ARG_PROPERTY,
                ARG_PRIVATE_USERS,
                ARG_KILL_SIGNAL,
                ARG_SETTINGS,
                ARG_CHDIR,
                ARG_PIVOT_ROOT,
                ARG_PRIVATE_USERS_CHOWN,
                ARG_PRIVATE_USERS_OWNERSHIP,
                ARG_NOTIFY_READY,
                ARG_ROOT_HASH,
                ARG_ROOT_HASH_SIG,
                ARG_VERITY_DATA,
                ARG_SYSTEM_CALL_FILTER,
                ARG_RLIMIT,
                ARG_HOSTNAME,
                ARG_NO_NEW_PRIVILEGES,
                ARG_OOM_SCORE_ADJUST,
                ARG_CPU_AFFINITY,
                ARG_RESOLV_CONF,
                ARG_TIMEZONE,
                ARG_CONSOLE,
                ARG_PIPE,
                ARG_OCI_BUNDLE,
                ARG_NO_PAGER,
                ARG_SET_CREDENTIAL,
                ARG_LOAD_CREDENTIAL,
                ARG_BIND_USER,
                ARG_SUPPRESS_SYNC,
                ARG_IMAGE_POLICY,
        };

        static const struct option options[] = {
                { "help",                   no_argument,       NULL, 'h'                        },
                { "version",                no_argument,       NULL, ARG_VERSION                },
                { "directory",              required_argument, NULL, 'D'                        },
                { "template",               required_argument, NULL, ARG_TEMPLATE               },
                { "ephemeral",              no_argument,       NULL, 'x'                        },
                { "user",                   required_argument, NULL, 'u'                        },
                { "private-network",        no_argument,       NULL, ARG_PRIVATE_NETWORK        },
                { "as-pid2",                no_argument,       NULL, 'a'                        },
                { "boot",                   no_argument,       NULL, 'b'                        },
                { "uuid",                   required_argument, NULL, ARG_UUID                   },
                { "read-only",              no_argument,       NULL, ARG_READ_ONLY              },
                { "capability",             required_argument, NULL, ARG_CAPABILITY             },
                { "ambient-capability",     required_argument, NULL, ARG_AMBIENT_CAPABILITY     },
                { "drop-capability",        required_argument, NULL, ARG_DROP_CAPABILITY        },
                { "no-new-privileges",      required_argument, NULL, ARG_NO_NEW_PRIVILEGES      },
                { "link-journal",           required_argument, NULL, ARG_LINK_JOURNAL           },
                { "bind",                   required_argument, NULL, ARG_BIND                   },
                { "bind-ro",                required_argument, NULL, ARG_BIND_RO                },
                { "tmpfs",                  required_argument, NULL, ARG_TMPFS                  },
                { "overlay",                required_argument, NULL, ARG_OVERLAY                },
                { "overlay-ro",             required_argument, NULL, ARG_OVERLAY_RO             },
                { "inaccessible",           required_argument, NULL, ARG_INACCESSIBLE           },
                { "machine",                required_argument, NULL, 'M'                        },
                { "hostname",               required_argument, NULL, ARG_HOSTNAME               },
                { "slice",                  required_argument, NULL, 'S'                        },
                { "setenv",                 required_argument, NULL, 'E'                        },
                { "selinux-context",        required_argument, NULL, 'Z'                        },
                { "selinux-apifs-context",  required_argument, NULL, 'L'                        },
                { "quiet",                  no_argument,       NULL, 'q'                        },
                { "share-system",           no_argument,       NULL, ARG_SHARE_SYSTEM           }, /* not documented */
                { "register",               required_argument, NULL, ARG_REGISTER               },
                { "keep-unit",              no_argument,       NULL, ARG_KEEP_UNIT              },
                { "network-interface",      required_argument, NULL, ARG_NETWORK_INTERFACE      },
                { "network-macvlan",        required_argument, NULL, ARG_NETWORK_MACVLAN        },
                { "network-ipvlan",         required_argument, NULL, ARG_NETWORK_IPVLAN         },
                { "network-veth",           no_argument,       NULL, 'n'                        },
                { "network-veth-extra",     required_argument, NULL, ARG_NETWORK_VETH_EXTRA     },
                { "network-bridge",         required_argument, NULL, ARG_NETWORK_BRIDGE         },
                { "network-zone",           required_argument, NULL, ARG_NETWORK_ZONE           },
                { "network-namespace-path", required_argument, NULL, ARG_NETWORK_NAMESPACE_PATH },
                { "personality",            required_argument, NULL, ARG_PERSONALITY            },
                { "image",                  required_argument, NULL, 'i'                        },
                { "volatile",               optional_argument, NULL, ARG_VOLATILE               },
                { "port",                   required_argument, NULL, 'p'                        },
                { "property",               required_argument, NULL, ARG_PROPERTY               },
                { "private-users",          optional_argument, NULL, ARG_PRIVATE_USERS          },
                { "private-users-chown",    optional_argument, NULL, ARG_PRIVATE_USERS_CHOWN    }, /* obsolete */
                { "private-users-ownership",required_argument, NULL, ARG_PRIVATE_USERS_OWNERSHIP},
                { "kill-signal",            required_argument, NULL, ARG_KILL_SIGNAL            },
                { "settings",               required_argument, NULL, ARG_SETTINGS               },
                { "chdir",                  required_argument, NULL, ARG_CHDIR                  },
                { "pivot-root",             required_argument, NULL, ARG_PIVOT_ROOT             },
                { "notify-ready",           required_argument, NULL, ARG_NOTIFY_READY           },
                { "root-hash",              required_argument, NULL, ARG_ROOT_HASH              },
                { "root-hash-sig",          required_argument, NULL, ARG_ROOT_HASH_SIG          },
                { "verity-data",            required_argument, NULL, ARG_VERITY_DATA            },
                { "system-call-filter",     required_argument, NULL, ARG_SYSTEM_CALL_FILTER     },
                { "rlimit",                 required_argument, NULL, ARG_RLIMIT                 },
                { "oom-score-adjust",       required_argument, NULL, ARG_OOM_SCORE_ADJUST       },
                { "cpu-affinity",           required_argument, NULL, ARG_CPU_AFFINITY           },
                { "resolv-conf",            required_argument, NULL, ARG_RESOLV_CONF            },
                { "timezone",               required_argument, NULL, ARG_TIMEZONE               },
                { "console",                required_argument, NULL, ARG_CONSOLE                },
                { "pipe",                   no_argument,       NULL, ARG_PIPE                   },
                { "oci-bundle",             required_argument, NULL, ARG_OCI_BUNDLE             },
                { "no-pager",               no_argument,       NULL, ARG_NO_PAGER               },
                { "set-credential",         required_argument, NULL, ARG_SET_CREDENTIAL         },
                { "load-credential",        required_argument, NULL, ARG_LOAD_CREDENTIAL        },
                { "bind-user",              required_argument, NULL, ARG_BIND_USER              },
                { "suppress-sync",          required_argument, NULL, ARG_SUPPRESS_SYNC          },
                { "image-policy",           required_argument, NULL, ARG_IMAGE_POLICY           },
                {}
        };

        int c, r;
        uint64_t plus = 0, minus = 0;
        bool mask_all_settings = false, mask_no_settings = false;

        assert(argc >= 0);
        assert(argv);

        /* Resetting to 0 forces the invocation of an internal initialization routine of getopt_long()
         * that checks for GNU extensions in optstring ('-' or '+' at the beginning). */
        optind = 0;
        while ((c = getopt_long(argc, argv, "+hD:u:abL:M:jS:Z:qi:xp:nUE:P", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'D':
                        r = parse_path_argument(optarg, false, &arg_directory);
                        if (r < 0)
                                return r;

                        arg_settings_mask |= SETTING_DIRECTORY;
                        break;

                case ARG_TEMPLATE:
                        r = parse_path_argument(optarg, false, &arg_template);
                        if (r < 0)
                                return r;

                        arg_settings_mask |= SETTING_DIRECTORY;
                        break;

                case 'i':
                        r = parse_path_argument(optarg, false, &arg_image);
                        if (r < 0)
                                return r;

                        arg_settings_mask |= SETTING_DIRECTORY;
                        break;

                case ARG_OCI_BUNDLE:
                        r = parse_path_argument(optarg, false, &arg_oci_bundle);
                        if (r < 0)
                                return r;

                        break;

                case 'x':
                        arg_ephemeral = true;
                        arg_settings_mask |= SETTING_EPHEMERAL;
                        break;

                case 'u':
                        r = free_and_strdup(&arg_user, optarg);
                        if (r < 0)
                                return log_oom();

                        arg_settings_mask |= SETTING_USER;
                        break;

                case ARG_NETWORK_ZONE: {
                        _cleanup_free_ char *j = NULL;

                        j = strjoin("vz-", optarg);
                        if (!j)
                                return log_oom();

                        if (!ifname_valid(j))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Network zone name not valid: %s", j);

                        free_and_replace(arg_network_zone, j);

                        arg_network_veth = true;
                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;
                }

                case ARG_NETWORK_BRIDGE:

                        if (!ifname_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Bridge interface name not valid: %s", optarg);

                        r = free_and_strdup(&arg_network_bridge, optarg);
                        if (r < 0)
                                return log_oom();

                        _fallthrough_;
                case 'n':
                        arg_network_veth = true;
                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;

                case ARG_NETWORK_VETH_EXTRA:
                        r = veth_extra_parse(&arg_network_veth_extra, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --network-veth-extra= parameter: %s", optarg);

                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;

                case ARG_NETWORK_INTERFACE:
                        r = interface_pair_parse(&arg_network_interfaces, optarg);
                        if (r < 0)
                                return r;

                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;

                case ARG_NETWORK_MACVLAN:
                        r = macvlan_pair_parse(&arg_network_macvlan, optarg);
                        if (r < 0)
                                return r;

                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;

                case ARG_NETWORK_IPVLAN:
                        r = ipvlan_pair_parse(&arg_network_ipvlan, optarg);
                        if (r < 0)
                                return r;

                        _fallthrough_;
                case ARG_PRIVATE_NETWORK:
                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;

                case ARG_NETWORK_NAMESPACE_PATH:
                        r = parse_path_argument(optarg, false, &arg_network_namespace_path);
                        if (r < 0)
                                return r;

                        arg_settings_mask |= SETTING_NETWORK;
                        break;

                case 'b':
                        if (arg_start_mode == START_PID2)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--boot and --as-pid2 may not be combined.");

                        arg_start_mode = START_BOOT;
                        arg_settings_mask |= SETTING_START_MODE;
                        break;

                case 'a':
                        if (arg_start_mode == START_BOOT)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--boot and --as-pid2 may not be combined.");

                        arg_start_mode = START_PID2;
                        arg_settings_mask |= SETTING_START_MODE;
                        break;

                case ARG_UUID:
                        r = id128_from_string_nonzero(optarg, &arg_uuid);
                        if (r == -ENXIO)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Machine UUID may not be all zeroes.");
                        if (r < 0)
                                return log_error_errno(r, "Invalid UUID: %s", optarg);

                        arg_settings_mask |= SETTING_MACHINE_ID;
                        break;

                case 'S': {
                        _cleanup_free_ char *mangled = NULL;

                        r = unit_name_mangle_with_suffix(optarg, NULL, UNIT_NAME_MANGLE_WARN, ".slice", &mangled);
                        if (r < 0)
                                return log_oom();

                        free_and_replace(arg_slice, mangled);
                        arg_settings_mask |= SETTING_SLICE;
                        break;
                }

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

                case ARG_HOSTNAME:
                        if (isempty(optarg))
                                arg_hostname = mfree(arg_hostname);
                        else {
                                if (!hostname_is_valid(optarg, 0))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Invalid hostname: %s", optarg);

                                r = free_and_strdup(&arg_hostname, optarg);
                                if (r < 0)
                                        return log_oom();
                        }

                        arg_settings_mask |= SETTING_HOSTNAME;
                        break;

                case 'Z':
                        arg_selinux_context = optarg;
                        break;

                case 'L':
                        arg_selinux_apifs_context = optarg;
                        break;

                case ARG_READ_ONLY:
                        arg_read_only = true;
                        arg_settings_mask |= SETTING_READ_ONLY;
                        break;

                case ARG_AMBIENT_CAPABILITY: {
                        uint64_t m;
                        r = parse_capability_spec(optarg, &m);
                        if (r <= 0)
                                return r;
                        arg_caps_ambient |= m;
                        arg_settings_mask |= SETTING_CAPABILITY;
                        break;
                }
                case ARG_CAPABILITY:
                case ARG_DROP_CAPABILITY: {
                        uint64_t m;
                        r = parse_capability_spec(optarg, &m);
                        if (r <= 0)
                                return r;

                        if (c == ARG_CAPABILITY)
                                plus |= m;
                        else
                                minus |= m;
                        arg_settings_mask |= SETTING_CAPABILITY;
                        break;
                }
                case ARG_NO_NEW_PRIVILEGES:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --no-new-privileges= argument: %s", optarg);

                        arg_no_new_privileges = r;
                        arg_settings_mask |= SETTING_NO_NEW_PRIVILEGES;
                        break;

                case 'j':
                        arg_link_journal = LINK_GUEST;
                        arg_link_journal_try = true;
                        arg_settings_mask |= SETTING_LINK_JOURNAL;
                        break;

                case ARG_LINK_JOURNAL:
                        r = parse_link_journal(optarg, &arg_link_journal, &arg_link_journal_try);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse link journal mode %s", optarg);

                        arg_settings_mask |= SETTING_LINK_JOURNAL;
                        break;

                case ARG_BIND:
                case ARG_BIND_RO:
                        r = bind_mount_parse(&arg_custom_mounts, &arg_n_custom_mounts, optarg, c == ARG_BIND_RO);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --bind(-ro)= argument %s: %m", optarg);

                        arg_settings_mask |= SETTING_CUSTOM_MOUNTS;
                        break;

                case ARG_TMPFS:
                        r = tmpfs_mount_parse(&arg_custom_mounts, &arg_n_custom_mounts, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --tmpfs= argument %s: %m", optarg);

                        arg_settings_mask |= SETTING_CUSTOM_MOUNTS;
                        break;

                case ARG_OVERLAY:
                case ARG_OVERLAY_RO:
                        r = overlay_mount_parse(&arg_custom_mounts, &arg_n_custom_mounts, optarg, c == ARG_OVERLAY_RO);
                        if (r == -EADDRNOTAVAIL)
                                return log_error_errno(r, "--overlay(-ro)= needs at least two colon-separated directories specified.");
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --overlay(-ro)= argument %s: %m", optarg);

                        arg_settings_mask |= SETTING_CUSTOM_MOUNTS;
                        break;

                case ARG_INACCESSIBLE:
                        r = inaccessible_mount_parse(&arg_custom_mounts, &arg_n_custom_mounts, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --inaccessible= argument %s: %m", optarg);

                        arg_settings_mask |= SETTING_CUSTOM_MOUNTS;
                        break;

                case 'E':
                        r = strv_env_replace_strdup_passthrough(&arg_setenv, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Cannot assign environment variable %s: %m", optarg);

                        arg_settings_mask |= SETTING_ENVIRONMENT;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_SHARE_SYSTEM:
                        /* We don't officially support this anymore, except for compat reasons. People should use the
                         * $SYSTEMD_NSPAWN_SHARE_* environment variables instead. */
                        log_warning("Please do not use --share-system anymore, use $SYSTEMD_NSPAWN_SHARE_* instead.");
                        arg_clone_ns_flags = 0;
                        break;

                case ARG_REGISTER:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error("Failed to parse --register= argument: %s", optarg);
                                return r;
                        }

                        arg_register = r;
                        break;

                case ARG_KEEP_UNIT:
                        arg_keep_unit = true;
                        break;

                case ARG_PERSONALITY:

                        arg_personality = personality_from_string(optarg);
                        if (arg_personality == PERSONALITY_INVALID)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown or unsupported personality '%s'.", optarg);

                        arg_settings_mask |= SETTING_PERSONALITY;
                        break;

                case ARG_VOLATILE:

                        if (!optarg)
                                arg_volatile_mode = VOLATILE_YES;
                        else if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(volatile_mode, VolatileMode, _VOLATILE_MODE_MAX);
                                return 0;
                        } else {
                                VolatileMode m;

                                m = volatile_mode_from_string(optarg);
                                if (m < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Failed to parse --volatile= argument: %s", optarg);
                                else
                                        arg_volatile_mode = m;
                        }

                        arg_settings_mask |= SETTING_VOLATILE_MODE;
                        break;

                case 'p':
                        r = expose_port_parse(&arg_expose_ports, optarg);
                        if (r == -EEXIST)
                                return log_error_errno(r, "Duplicate port specification: %s", optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse host port %s: %m", optarg);

                        arg_settings_mask |= SETTING_EXPOSE_PORTS;
                        break;

                case ARG_PROPERTY:
                        if (strv_extend(&arg_property, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_PRIVATE_USERS: {
                        int boolean;

                        if (!optarg)
                                boolean = true;
                        else if (!in_charset(optarg, DIGITS))
                                /* do *not* parse numbers as booleans */
                                boolean = parse_boolean(optarg);
                        else
                                boolean = -1;

                        if (boolean == 0) {
                                /* no: User namespacing off */
                                arg_userns_mode = USER_NAMESPACE_NO;
                                arg_uid_shift = UID_INVALID;
                                arg_uid_range = UINT32_C(0x10000);
                        } else if (boolean > 0) {
                                /* yes: User namespacing on, UID range is read from root dir */
                                arg_userns_mode = USER_NAMESPACE_FIXED;
                                arg_uid_shift = UID_INVALID;
                                arg_uid_range = UINT32_C(0x10000);
                        } else if (streq(optarg, "pick")) {
                                /* pick: User namespacing on, UID range is picked randomly */
                                arg_userns_mode = USER_NAMESPACE_PICK; /* Note that arg_userns_ownership is
                                                                        * implied by USER_NAMESPACE_PICK
                                                                        * further down. */
                                arg_uid_shift = UID_INVALID;
                                arg_uid_range = UINT32_C(0x10000);

                        } else if (streq(optarg, "identity")) {
                                /* identity: User namespaces on, UID range is map the 0…0xFFFF range to
                                 * itself, i.e. we don't actually map anything, but do take benefit of
                                 * isolation of capability sets. */
                                arg_userns_mode = USER_NAMESPACE_FIXED;
                                arg_uid_shift = 0;
                                arg_uid_range = UINT32_C(0x10000);
                        } else {
                                _cleanup_free_ char *buffer = NULL;
                                const char *range, *shift;

                                /* anything else: User namespacing on, UID range is explicitly configured */

                                range = strchr(optarg, ':');
                                if (range) {
                                        buffer = strndup(optarg, range - optarg);
                                        if (!buffer)
                                                return log_oom();
                                        shift = buffer;

                                        range++;
                                        r = safe_atou32(range, &arg_uid_range);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to parse UID range \"%s\": %m", range);
                                } else
                                        shift = optarg;

                                r = parse_uid(shift, &arg_uid_shift);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse UID \"%s\": %m", optarg);

                                arg_userns_mode = USER_NAMESPACE_FIXED;

                                if (!userns_shift_range_valid(arg_uid_shift, arg_uid_range))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "UID range cannot be empty or go beyond " UID_FMT ".", UID_INVALID);
                        }

                        arg_settings_mask |= SETTING_USERNS;
                        break;
                }

                case 'U':
                        if (userns_supported()) {
                                arg_userns_mode = USER_NAMESPACE_PICK; /* Note that arg_userns_ownership is
                                                                        * implied by USER_NAMESPACE_PICK
                                                                        * further down. */
                                arg_uid_shift = UID_INVALID;
                                arg_uid_range = UINT32_C(0x10000);

                                arg_settings_mask |= SETTING_USERNS;
                        }

                        break;

                case ARG_PRIVATE_USERS_CHOWN:
                        arg_userns_ownership = USER_NAMESPACE_OWNERSHIP_CHOWN;

                        arg_settings_mask |= SETTING_USERNS;
                        break;

                case ARG_PRIVATE_USERS_OWNERSHIP:
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(user_namespace_ownership, UserNamespaceOwnership, _USER_NAMESPACE_OWNERSHIP_MAX);
                                return 0;
                        }

                        arg_userns_ownership = user_namespace_ownership_from_string(optarg);
                        if (arg_userns_ownership < 0)
                                return log_error_errno(arg_userns_ownership, "Cannot parse --user-namespace-ownership= value: %s", optarg);

                        arg_settings_mask |= SETTING_USERNS;
                        break;

                case ARG_KILL_SIGNAL:
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(signal, int, _NSIG);
                                return 0;
                        }

                        arg_kill_signal = signal_from_string(optarg);
                        if (arg_kill_signal < 0)
                                return log_error_errno(arg_kill_signal, "Cannot parse signal: %s", optarg);

                        arg_settings_mask |= SETTING_KILL_SIGNAL;
                        break;

                case ARG_SETTINGS:

                        /* no               → do not read files
                         * yes              → read files, do not override cmdline, trust only subset
                         * override         → read files, override cmdline, trust only subset
                         * trusted          → read files, do not override cmdline, trust all
                         */

                        r = parse_boolean(optarg);
                        if (r < 0) {
                                if (streq(optarg, "trusted")) {
                                        mask_all_settings = false;
                                        mask_no_settings = false;
                                        arg_settings_trusted = true;

                                } else if (streq(optarg, "override")) {
                                        mask_all_settings = false;
                                        mask_no_settings = true;
                                        arg_settings_trusted = -1;
                                } else
                                        return log_error_errno(r, "Failed to parse --settings= argument: %s", optarg);
                        } else if (r > 0) {
                                /* yes */
                                mask_all_settings = false;
                                mask_no_settings = false;
                                arg_settings_trusted = -1;
                        } else {
                                /* no */
                                mask_all_settings = true;
                                mask_no_settings = false;
                                arg_settings_trusted = false;
                        }

                        break;

                case ARG_CHDIR:
                        if (!path_is_absolute(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Working directory %s is not an absolute path.", optarg);

                        r = free_and_strdup(&arg_chdir, optarg);
                        if (r < 0)
                                return log_oom();

                        arg_settings_mask |= SETTING_WORKING_DIRECTORY;
                        break;

                case ARG_PIVOT_ROOT:
                        r = pivot_root_parse(&arg_pivot_root_new, &arg_pivot_root_old, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --pivot-root= argument %s: %m", optarg);

                        arg_settings_mask |= SETTING_PIVOT_ROOT;
                        break;

                case ARG_NOTIFY_READY:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "%s is not a valid notify mode. Valid modes are: yes, no, and ready.", optarg);
                        arg_notify_ready = r;
                        arg_settings_mask |= SETTING_NOTIFY_READY;
                        break;

                case ARG_ROOT_HASH: {
                        _cleanup_free_ void *k = NULL;
                        size_t l;

                        r = unhexmem(optarg, strlen(optarg), &k, &l);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse root hash: %s", optarg);
                        if (l < sizeof(sd_id128_t))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Root hash must be at least 128-bit long: %s", optarg);

                        free_and_replace(arg_verity_settings.root_hash, k);
                        arg_verity_settings.root_hash_size = l;
                        break;
                }

                case ARG_ROOT_HASH_SIG: {
                        char *value;
                        size_t l;
                        void *p;

                        if ((value = startswith(optarg, "base64:"))) {
                                r = unbase64mem(value, strlen(value), &p, &l);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse root hash signature '%s': %m", optarg);

                        } else {
                                r = read_full_file(optarg, (char**) &p, &l);
                                if (r < 0)
                                        return log_error_errno(r, "Failed parse root hash signature file '%s': %m", optarg);
                        }

                        free_and_replace(arg_verity_settings.root_hash_sig, p);
                        arg_verity_settings.root_hash_sig_size = l;
                        break;
                }

                case ARG_VERITY_DATA:
                        r = parse_path_argument(optarg, false, &arg_verity_settings.data_path);
                        if (r < 0)
                                return r;
                        break;

                case ARG_SYSTEM_CALL_FILTER: {
                        bool negative;
                        const char *items;

                        negative = optarg[0] == '~';
                        items = negative ? optarg + 1 : optarg;

                        for (;;) {
                                _cleanup_free_ char *word = NULL;

                                r = extract_first_word(&items, &word, NULL, 0);
                                if (r == 0)
                                        break;
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse system call filter: %m");

                                if (negative)
                                        r = strv_extend(&arg_syscall_deny_list, word);
                                else
                                        r = strv_extend(&arg_syscall_allow_list, word);
                                if (r < 0)
                                        return log_oom();
                        }

                        arg_settings_mask |= SETTING_SYSCALL_FILTER;
                        break;
                }

                case ARG_RLIMIT: {
                        const char *eq;
                        _cleanup_free_ char *name = NULL;
                        int rl;

                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(rlimit, int, _RLIMIT_MAX);
                                return 0;
                        }

                        eq = strchr(optarg, '=');
                        if (!eq)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--rlimit= expects an '=' assignment.");

                        name = strndup(optarg, eq - optarg);
                        if (!name)
                                return log_oom();

                        rl = rlimit_from_string_harder(name);
                        if (rl < 0)
                                return log_error_errno(rl, "Unknown resource limit: %s", name);

                        if (!arg_rlimit[rl]) {
                                arg_rlimit[rl] = new0(struct rlimit, 1);
                                if (!arg_rlimit[rl])
                                        return log_oom();
                        }

                        r = rlimit_parse(rl, eq + 1, arg_rlimit[rl]);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse resource limit: %s", eq + 1);

                        arg_settings_mask |= SETTING_RLIMIT_FIRST << rl;
                        break;
                }

                case ARG_OOM_SCORE_ADJUST:
                        r = parse_oom_score_adjust(optarg, &arg_oom_score_adjust);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --oom-score-adjust= parameter: %s", optarg);

                        arg_oom_score_adjust_set = true;
                        arg_settings_mask |= SETTING_OOM_SCORE_ADJUST;
                        break;

                case ARG_CPU_AFFINITY: {
                        CPUSet cpuset;

                        r = parse_cpu_set(optarg, &cpuset);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse CPU affinity mask %s: %m", optarg);

                        cpu_set_reset(&arg_cpu_set);
                        arg_cpu_set = cpuset;
                        arg_settings_mask |= SETTING_CPU_AFFINITY;
                        break;
                }

                case ARG_RESOLV_CONF:
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(resolv_conf_mode, ResolvConfMode, _RESOLV_CONF_MODE_MAX);
                                return 0;
                        }

                        arg_resolv_conf = resolv_conf_mode_from_string(optarg);
                        if (arg_resolv_conf < 0)
                                return log_error_errno(arg_resolv_conf,
                                                       "Failed to parse /etc/resolv.conf mode: %s", optarg);

                        arg_settings_mask |= SETTING_RESOLV_CONF;
                        break;

                case ARG_TIMEZONE:
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(timezone_mode, TimezoneMode, _TIMEZONE_MODE_MAX);
                                return 0;
                        }

                        arg_timezone = timezone_mode_from_string(optarg);
                        if (arg_timezone < 0)
                                return log_error_errno(arg_timezone,
                                                       "Failed to parse /etc/localtime mode: %s", optarg);

                        arg_settings_mask |= SETTING_TIMEZONE;
                        break;

                case ARG_CONSOLE:
                        r = handle_arg_console(optarg);
                        if (r <= 0)
                                return r;
                        break;

                case 'P':
                case ARG_PIPE:
                        r = handle_arg_console("pipe");
                        if (r <= 0)
                                return r;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_SET_CREDENTIAL:
                        r = machine_credential_set(&arg_credentials, optarg);
                        if (r < 0)
                                return r;

                        arg_settings_mask |= SETTING_CREDENTIALS;
                        break;

                case ARG_LOAD_CREDENTIAL:
                        r = machine_credential_load(&arg_credentials, optarg);
                        if (r < 0)
                                return r;

                        arg_settings_mask |= SETTING_CREDENTIALS;
                        break;

                case ARG_BIND_USER:
                        if (!valid_user_group_name(optarg, 0))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid user name to bind: %s", optarg);

                        if (strv_extend(&arg_bind_user, optarg) < 0)
                                return log_oom();

                        arg_settings_mask |= SETTING_BIND_USER;
                        break;

                case ARG_SUPPRESS_SYNC:
                        r = parse_boolean_argument("--suppress-sync=", optarg, &arg_suppress_sync);
                        if (r < 0)
                                return r;

                        arg_settings_mask |= SETTING_SUPPRESS_SYNC;
                        break;

                case ARG_IMAGE_POLICY:
                        r = parse_image_policy_argument(optarg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (argc > optind) {
                strv_free(arg_parameters);
                arg_parameters = strv_copy(argv + optind);
                if (!arg_parameters)
                        return log_oom();

                arg_settings_mask |= SETTING_START_MODE;
        }

        if (arg_ephemeral && arg_template && !arg_directory)
                /* User asked for ephemeral execution but specified --template= instead of --directory=. Semantically
                 * such an invocation makes some sense, see https://github.com/systemd/systemd/issues/3667. Let's
                 * accept this here, and silently make "--ephemeral --template=" equivalent to "--ephemeral
                 * --directory=". */
                arg_directory = TAKE_PTR(arg_template);

        arg_caps_retain |= plus;
        arg_caps_retain |= arg_private_network ? UINT64_C(1) << CAP_NET_ADMIN : 0;
        arg_caps_retain &= ~minus;

        /* Make sure to parse environment before we reset the settings mask below */
        r = parse_environment();
        if (r < 0)
                return r;

        /* Load all settings from .nspawn files */
        if (mask_no_settings)
                arg_settings_mask = 0;

        /* Don't load any settings from .nspawn files */
        if (mask_all_settings)
                arg_settings_mask = _SETTINGS_MASK_ALL;

        return 1;
}

static int verify_arguments(void) {
        int r;

        if (arg_start_mode == START_PID2 && arg_unified_cgroup_hierarchy == CGROUP_UNIFIED_UNKNOWN) {
                /* If we are running the stub init in the container, we don't need to look at what the init
                 * in the container supports, because we are not using it. Let's immediately pick the right
                 * setting based on the host system configuration.
                 *
                 * We only do this, if the user didn't use an environment variable to override the detection.
                 */

                r = cg_all_unified();
                if (r < 0)
                        return log_error_errno(r, "Failed to determine whether we are in all unified mode.");
                if (r > 0)
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_ALL;
                else if (cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER) > 0)
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_SYSTEMD;
                else
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_NONE;
        }

        if (arg_userns_mode != USER_NAMESPACE_NO)
                arg_mount_settings |= MOUNT_USE_USERNS;

        if (arg_private_network)
                arg_mount_settings |= MOUNT_APPLY_APIVFS_NETNS;

        if (!(arg_clone_ns_flags & CLONE_NEWPID) ||
            !(arg_clone_ns_flags & CLONE_NEWUTS)) {
                arg_register = false;
                if (arg_start_mode != START_PID1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--boot cannot be used without namespacing.");
        }

        if (arg_userns_ownership < 0)
                arg_userns_ownership =
                        arg_userns_mode == USER_NAMESPACE_PICK ? USER_NAMESPACE_OWNERSHIP_AUTO :
                                                                 USER_NAMESPACE_OWNERSHIP_OFF;

        if (arg_start_mode == START_BOOT && arg_kill_signal <= 0)
                arg_kill_signal = SIGRTMIN+3;

        if (arg_volatile_mode != VOLATILE_NO) /* Make sure all file systems contained in the image are mounted read-only if we are in volatile mode */
                arg_read_only = true;

        if (has_custom_root_mount(arg_custom_mounts, arg_n_custom_mounts))
                arg_read_only = true;

        if (arg_keep_unit && arg_register && cg_pid_get_owner_uid(0, NULL) >= 0)
                /* Save the user from accidentally registering either user-$SESSION.scope or user@.service.
                 * The latter is not technically a user session, but we don't need to labour the point. */
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--keep-unit --register=yes may not be used when invoked from a user session.");

        if (arg_directory && arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--directory= and --image= may not be combined.");

        if (arg_template && arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--template= and --image= may not be combined.");

        if (arg_template && !(arg_directory || arg_machine))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--template= needs --directory= or --machine=.");

        if (arg_ephemeral && arg_template)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--ephemeral and --template= may not be combined.");

        if (arg_ephemeral && !IN_SET(arg_link_journal, LINK_NO, LINK_AUTO))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--ephemeral and --link-journal= may not be combined.");

        if (arg_userns_mode != USER_NAMESPACE_NO && !userns_supported())
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "--private-users= is not supported, kernel compiled without user namespace support.");

        if (arg_userns_ownership == USER_NAMESPACE_OWNERSHIP_CHOWN && arg_read_only)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--read-only and --private-users-ownership=chown may not be combined.");

        /* We don't support --private-users-ownership=chown together with any of the volatile modes since we
         * couldn't change the read-only part of the tree (i.e. /usr) anyway, or because it would trigger a
         * massive copy-up (in case of overlay) making the entire exercise pointless. */
        if (arg_userns_ownership == USER_NAMESPACE_OWNERSHIP_CHOWN && arg_volatile_mode != VOLATILE_NO)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--volatile= and --private-users-ownership=chown may not be combined.");

        /* If --network-namespace-path is given with any other network-related option (except --private-network),
         * we need to error out, to avoid conflicts between different network options. */
        if (arg_network_namespace_path &&
                (arg_network_interfaces || arg_network_macvlan ||
                 arg_network_ipvlan || arg_network_veth_extra ||
                 arg_network_bridge || arg_network_zone ||
                 arg_network_veth))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--network-namespace-path= cannot be combined with other network options.");

        if (arg_network_bridge && arg_network_zone)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "--network-bridge= and --network-zone= may not be combined.");

        if (arg_userns_mode != USER_NAMESPACE_NO && (arg_mount_settings & MOUNT_APPLY_APIVFS_NETNS) && !arg_private_network)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid namespacing settings. Mounting sysfs with --private-users requires --private-network.");

        if (arg_userns_mode != USER_NAMESPACE_NO && !(arg_mount_settings & MOUNT_APPLY_APIVFS_RO))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot combine --private-users with read-write mounts.");

        if (arg_expose_ports && !arg_private_network)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot use --port= without private networking.");

        if (arg_caps_ambient) {
                if (arg_caps_ambient == UINT64_MAX)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "AmbientCapability= does not support the value all.");

                if ((arg_caps_ambient & arg_caps_retain) != arg_caps_ambient)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "AmbientCapability= setting is not fully covered by Capability= setting.");

                if (arg_start_mode == START_BOOT)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "AmbientCapability= setting is not useful for boot mode.");
        }

        if (arg_userns_mode == USER_NAMESPACE_NO && !strv_isempty(arg_bind_user))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--bind-user= requires --private-users");

        /* Drop duplicate --bind-user= entries */
        strv_uniq(arg_bind_user);

        r = custom_mount_check_all();
        if (r < 0)
                return r;

        return 0;
}

static int verify_network_interfaces_initialized(void) {
        int r;
        r = test_network_interfaces_initialized(arg_network_interfaces);
        if (r < 0)
                return r;

        r = test_network_interfaces_initialized(arg_network_macvlan);
        if (r < 0)
                return r;

        r = test_network_interfaces_initialized(arg_network_ipvlan);
        if (r < 0)
                return r;

        return 0;
}

int userns_lchown(const char *p, uid_t uid, gid_t gid) {
        assert(p);

        if (arg_userns_mode == USER_NAMESPACE_NO)
                return 0;

        if (uid == UID_INVALID && gid == GID_INVALID)
                return 0;

        if (uid != UID_INVALID) {
                uid += arg_uid_shift;

                if (uid < arg_uid_shift || uid >= arg_uid_shift + arg_uid_range)
                        return -EOVERFLOW;
        }

        if (gid != GID_INVALID) {
                gid += (gid_t) arg_uid_shift;

                if (gid < (gid_t) arg_uid_shift || gid >= (gid_t) (arg_uid_shift + arg_uid_range))
                        return -EOVERFLOW;
        }

        return RET_NERRNO(lchown(p, uid, gid));
}

int userns_mkdir(const char *root, const char *path, mode_t mode, uid_t uid, gid_t gid) {
        const char *q;
        int r;

        q = prefix_roota(root, path);
        r = RET_NERRNO(mkdir(q, mode));
        if (r == -EEXIST)
                return 0;
        if (r < 0)
                return r;

        return userns_lchown(q, uid, gid);
}

static const char *timezone_from_path(const char *path) {
        return PATH_STARTSWITH_SET(
                        path,
                        "../usr/share/zoneinfo/",
                        "/usr/share/zoneinfo/");
}

static bool etc_writable(void) {
        return !arg_read_only || IN_SET(arg_volatile_mode, VOLATILE_YES, VOLATILE_OVERLAY);
}

static int setup_timezone(const char *dest) {
        _cleanup_free_ char *p = NULL, *etc = NULL;
        const char *where, *check;
        TimezoneMode m;
        int r;

        assert(dest);

        if (IN_SET(arg_timezone, TIMEZONE_AUTO, TIMEZONE_SYMLINK)) {
                r = readlink_malloc("/etc/localtime", &p);
                if (r == -ENOENT && arg_timezone == TIMEZONE_AUTO)
                        m = etc_writable() ? TIMEZONE_DELETE : TIMEZONE_OFF;
                else if (r == -EINVAL && arg_timezone == TIMEZONE_AUTO) /* regular file? */
                        m = etc_writable() ? TIMEZONE_COPY : TIMEZONE_BIND;
                else if (r < 0) {
                        log_warning_errno(r, "Failed to read host's /etc/localtime symlink, not updating container timezone: %m");
                        /* To handle warning, delete /etc/localtime and replace it with a symbolic link to a time zone data
                         * file.
                         *
                         * Example:
                         * ln -s /usr/share/zoneinfo/UTC /etc/localtime
                         */
                        return 0;
                } else if (arg_timezone == TIMEZONE_AUTO)
                        m = etc_writable() ? TIMEZONE_SYMLINK : TIMEZONE_BIND;
                else
                        m = arg_timezone;
        } else
                m = arg_timezone;

        if (m == TIMEZONE_OFF)
                return 0;

        r = chase("/etc", dest, CHASE_PREFIX_ROOT, &etc, NULL);
        if (r < 0) {
                log_warning_errno(r, "Failed to resolve /etc path in container, ignoring: %m");
                return 0;
        }

        where = strjoina(etc, "/localtime");

        switch (m) {

        case TIMEZONE_DELETE:
                if (unlink(where) < 0)
                        log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno, "Failed to remove '%s', ignoring: %m", where);

                return 0;

        case TIMEZONE_SYMLINK: {
                _cleanup_free_ char *q = NULL;
                const char *z, *what;

                z = timezone_from_path(p);
                if (!z) {
                        log_warning("/etc/localtime does not point into /usr/share/zoneinfo/, not updating container timezone.");
                        return 0;
                }

                r = readlink_malloc(where, &q);
                if (r >= 0 && streq_ptr(timezone_from_path(q), z))
                        return 0; /* Already pointing to the right place? Then do nothing .. */

                check = strjoina(dest, "/usr/share/zoneinfo/", z);
                r = chase(check, dest, 0, NULL, NULL);
                if (r < 0)
                        log_debug_errno(r, "Timezone %s does not exist (or is not accessible) in container, not creating symlink: %m", z);
                else {
                        if (unlink(where) < 0 && errno != ENOENT) {
                                log_full_errno(IN_SET(errno, EROFS, EACCES, EPERM) ? LOG_DEBUG : LOG_WARNING, /* Don't complain on read-only images */
                                               errno, "Failed to remove existing timezone info %s in container, ignoring: %m", where);
                                return 0;
                        }

                        what = strjoina("../usr/share/zoneinfo/", z);
                        if (symlink(what, where) < 0) {
                                log_full_errno(IN_SET(errno, EROFS, EACCES, EPERM) ? LOG_DEBUG : LOG_WARNING,
                                               errno, "Failed to correct timezone of container, ignoring: %m");
                                return 0;
                        }

                        break;
                }

                _fallthrough_;
        }

        case TIMEZONE_BIND: {
                _cleanup_free_ char *resolved = NULL;
                int found;

                found = chase(where, dest, CHASE_NONEXISTENT, &resolved, NULL);
                if (found < 0) {
                        log_warning_errno(found, "Failed to resolve /etc/localtime path in container, ignoring: %m");
                        return 0;
                }

                if (found == 0) /* missing? */
                        (void) touch(resolved);

                r = mount_nofollow_verbose(LOG_WARNING, "/etc/localtime", resolved, NULL, MS_BIND, NULL);
                if (r >= 0)
                        return mount_nofollow_verbose(LOG_ERR, NULL, resolved, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV, NULL);

                _fallthrough_;
        }

        case TIMEZONE_COPY:
                /* If mounting failed, try to copy */
                r = copy_file_atomic("/etc/localtime", where, 0644, COPY_REFLINK|COPY_REPLACE);
                if (r < 0) {
                        log_full_errno(IN_SET(r, -EROFS, -EACCES, -EPERM) ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to copy /etc/localtime to %s, ignoring: %m", where);
                        return 0;
                }

                break;

        default:
                assert_not_reached();
        }

        /* Fix permissions of the symlink or file copy we just created */
        r = userns_lchown(where, 0, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to chown /etc/localtime, ignoring: %m");

        return 0;
}

static int have_resolv_conf(const char *path) {
        assert(path);

        if (access(path, F_OK) < 0) {
                if (errno == ENOENT)
                        return 0;

                return log_debug_errno(errno, "Failed to determine whether '%s' is available: %m", path);
        }

        return 1;
}

static int resolved_listening(void) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *dns_stub_listener_mode = NULL;
        int r;

        /* Check if resolved is listening */

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_debug_errno(r, "Failed to open system bus: %m");

        r = bus_name_has_owner(bus, "org.freedesktop.resolve1", NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to check whether the 'org.freedesktop.resolve1' bus name is taken: %m");
        if (r == 0)
                return 0;

        r = bus_get_property_string(bus, bus_resolve_mgr, "DNSStubListener", &error, &dns_stub_listener_mode);
        if (r < 0)
                return log_debug_errno(r, "Failed to query DNSStubListener property: %s", bus_error_message(&error, r));

        return STR_IN_SET(dns_stub_listener_mode, "udp", "yes");
}

static int setup_resolv_conf(const char *dest) {
        _cleanup_free_ char *etc = NULL;
        const char *where, *what;
        ResolvConfMode m;
        int r;

        assert(dest);

        if (arg_resolv_conf == RESOLV_CONF_AUTO) {
                if (arg_private_network)
                        m = RESOLV_CONF_OFF;
                else if (have_resolv_conf(PRIVATE_STUB_RESOLV_CONF) > 0 && resolved_listening() > 0)
                        m = etc_writable() ? RESOLV_CONF_COPY_STUB : RESOLV_CONF_BIND_STUB;
                else if (have_resolv_conf("/etc/resolv.conf") > 0)
                        m = etc_writable() ? RESOLV_CONF_COPY_HOST : RESOLV_CONF_BIND_HOST;
                else
                        m = etc_writable() ? RESOLV_CONF_DELETE : RESOLV_CONF_OFF;

        } else
                m = arg_resolv_conf;

        if (m == RESOLV_CONF_OFF)
                return 0;

        r = chase("/etc", dest, CHASE_PREFIX_ROOT, &etc, NULL);
        if (r < 0) {
                log_warning_errno(r, "Failed to resolve /etc path in container, ignoring: %m");
                return 0;
        }

        where = strjoina(etc, "/resolv.conf");

        if (m == RESOLV_CONF_DELETE) {
                if (unlink(where) < 0)
                        log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno, "Failed to remove '%s', ignoring: %m", where);

                return 0;
        }

        if (IN_SET(m, RESOLV_CONF_BIND_STATIC, RESOLV_CONF_REPLACE_STATIC, RESOLV_CONF_COPY_STATIC))
                what = PRIVATE_STATIC_RESOLV_CONF;
        else if (IN_SET(m, RESOLV_CONF_BIND_UPLINK, RESOLV_CONF_REPLACE_UPLINK, RESOLV_CONF_COPY_UPLINK))
                what = PRIVATE_UPLINK_RESOLV_CONF;
        else if (IN_SET(m, RESOLV_CONF_BIND_STUB, RESOLV_CONF_REPLACE_STUB, RESOLV_CONF_COPY_STUB))
                what = PRIVATE_STUB_RESOLV_CONF;
        else
                what = "/etc/resolv.conf";

        if (IN_SET(m, RESOLV_CONF_BIND_HOST, RESOLV_CONF_BIND_STATIC, RESOLV_CONF_BIND_UPLINK, RESOLV_CONF_BIND_STUB)) {
                _cleanup_free_ char *resolved = NULL;
                int found;

                found = chase(where, dest, CHASE_NONEXISTENT|CHASE_NOFOLLOW, &resolved, NULL);
                if (found < 0) {
                        log_warning_errno(found, "Failed to resolve /etc/resolv.conf path in container, ignoring: %m");
                        return 0;
                }

                if (found == 0) /* missing? */
                        (void) touch(resolved);

                r = mount_nofollow_verbose(LOG_WARNING, what, resolved, NULL, MS_BIND, NULL);
                if (r >= 0)
                        return mount_nofollow_verbose(LOG_ERR, NULL, resolved, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV, NULL);

                /* If that didn't work, let's copy the file */
        }

        if (IN_SET(m, RESOLV_CONF_REPLACE_HOST, RESOLV_CONF_REPLACE_STATIC, RESOLV_CONF_REPLACE_UPLINK, RESOLV_CONF_REPLACE_STUB))
                r = copy_file_atomic(what, where, 0644, COPY_REFLINK|COPY_REPLACE);
        else
                r = copy_file(what, where, O_TRUNC|O_NOFOLLOW, 0644, COPY_REFLINK);
        if (r < 0) {
                /* If the file already exists as symlink, let's suppress the warning, under the assumption that
                 * resolved or something similar runs inside and the symlink points there.
                 *
                 * If the disk image is read-only, there's also no point in complaining.
                 */
                log_full_errno(!IN_SET(RESOLV_CONF_COPY_HOST, RESOLV_CONF_COPY_STATIC, RESOLV_CONF_COPY_UPLINK, RESOLV_CONF_COPY_STUB) &&
                               IN_SET(r, -ELOOP, -EROFS, -EACCES, -EPERM) ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to copy /etc/resolv.conf to %s, ignoring: %m", where);
                return 0;
        }

        r = userns_lchown(where, 0, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to chown /etc/resolv.conf, ignoring: %m");

        return 0;
}

static int setup_boot_id(void) {
        _cleanup_(unlink_and_freep) char *from = NULL;
        _cleanup_free_ char *path = NULL;
        sd_id128_t rnd = SD_ID128_NULL;
        const char *to;
        int r;

        /* Generate a new randomized boot ID, so that each boot-up of the container gets a new one */

        r = tempfn_random_child("/run", "proc-sys-kernel-random-boot-id", &path);
        if (r < 0)
                return log_error_errno(r, "Failed to generate random boot ID path: %m");

        r = sd_id128_randomize(&rnd);
        if (r < 0)
                return log_error_errno(r, "Failed to generate random boot id: %m");

        r = id128_write(path, ID128_FORMAT_UUID, rnd);
        if (r < 0)
                return log_error_errno(r, "Failed to write boot id: %m");

        from = TAKE_PTR(path);
        to = "/proc/sys/kernel/random/boot_id";

        r = mount_nofollow_verbose(LOG_ERR, from, to, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        return mount_nofollow_verbose(LOG_ERR, NULL, to, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
}

static int copy_devnodes(const char *dest) {
        static const char devnodes[] =
                "null\0"
                "zero\0"
                "full\0"
                "random\0"
                "urandom\0"
                "tty\0"
                "net/tun\0";

        int r = 0;

        assert(dest);

        BLOCK_WITH_UMASK(0000);

        /* Create /dev/net, so that we can create /dev/net/tun in it */
        if (userns_mkdir(dest, "/dev/net", 0755, 0, 0) < 0)
                return log_error_errno(r, "Failed to create /dev/net directory: %m");

        NULSTR_FOREACH(d, devnodes) {
                _cleanup_free_ char *from = NULL, *to = NULL;
                struct stat st;

                from = path_join("/dev/", d);
                if (!from)
                        return log_oom();

                to = path_join(dest, from);
                if (!to)
                        return log_oom();

                if (stat(from, &st) < 0) {

                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to stat %s: %m", from);

                } else if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "%s is not a char or block device, cannot copy.", from);
                else {
                        _cleanup_free_ char *sl = NULL, *prefixed = NULL, *dn = NULL, *t = NULL;

                        if (mknod(to, st.st_mode, st.st_rdev) < 0) {
                                /* Explicitly warn the user when /dev is already populated. */
                                if (errno == EEXIST)
                                        log_notice("%s/dev/ is pre-mounted and pre-populated. If a pre-mounted /dev/ is provided it needs to be an unpopulated file system.", dest);
                                if (errno != EPERM)
                                        return log_error_errno(errno, "mknod(%s) failed: %m", to);

                                /* Some systems abusively restrict mknod but allow bind mounts. */
                                r = touch(to);
                                if (r < 0)
                                        return log_error_errno(r, "touch (%s) failed: %m", to);
                                r = mount_nofollow_verbose(LOG_DEBUG, from, to, NULL, MS_BIND, NULL);
                                if (r < 0)
                                        return log_error_errno(r, "Both mknod and bind mount (%s) failed: %m", to);
                        }

                        r = userns_lchown(to, 0, 0);
                        if (r < 0)
                                return log_error_errno(r, "chown() of device node %s failed: %m", to);

                        dn = path_join("/dev", S_ISCHR(st.st_mode) ? "char" : "block");
                        if (!dn)
                                return log_oom();

                        r = userns_mkdir(dest, dn, 0755, 0, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create '%s': %m", dn);

                        if (asprintf(&sl, "%s/%u:%u", dn, major(st.st_rdev), minor(st.st_rdev)) < 0)
                                return log_oom();

                        prefixed = path_join(dest, sl);
                        if (!prefixed)
                                return log_oom();

                        t = path_join("..", d);
                        if (!t)
                                return log_oom();

                        if (symlink(t, prefixed) < 0)
                                log_debug_errno(errno, "Failed to symlink '%s' to '%s': %m", t, prefixed);
                }
        }

        return r;
}

static int make_extra_nodes(const char *dest) {
        size_t i;
        int r;

        BLOCK_WITH_UMASK(0000);

        for (i = 0; i < arg_n_extra_nodes; i++) {
                _cleanup_free_ char *path = NULL;
                DeviceNode *n = arg_extra_nodes + i;

                path = path_join(dest, n->path);
                if (!path)
                        return log_oom();

                if (mknod(path, n->mode, S_ISCHR(n->mode) || S_ISBLK(n->mode) ? makedev(n->major, n->minor) : 0) < 0)
                        return log_error_errno(errno, "Failed to create device node '%s': %m", path);

                r = chmod_and_chown(path, n->mode, n->uid, n->gid);
                if (r < 0)
                        return log_error_errno(r, "Failed to adjust device node ownership of '%s': %m", path);
        }

        return 0;
}

static int setup_pts(const char *dest) {
        _cleanup_free_ char *options = NULL;
        const char *p;
        int r;

#if HAVE_SELINUX
        if (arg_selinux_apifs_context)
                (void) asprintf(&options,
                                "newinstance,ptmxmode=0666,mode=620,gid=" GID_FMT ",context=\"%s\"",
                                arg_uid_shift + TTY_GID,
                                arg_selinux_apifs_context);
        else
#endif
                (void) asprintf(&options,
                                "newinstance,ptmxmode=0666,mode=620,gid=" GID_FMT,
                                arg_uid_shift + TTY_GID);

        if (!options)
                return log_oom();

        /* Mount /dev/pts itself */
        p = prefix_roota(dest, "/dev/pts");
        r = RET_NERRNO(mkdir(p, 0755));
        if (r < 0)
                return log_error_errno(r, "Failed to create /dev/pts: %m");

        r = mount_nofollow_verbose(LOG_ERR, "devpts", p, "devpts", MS_NOSUID|MS_NOEXEC, options);
        if (r < 0)
                return r;
        r = userns_lchown(p, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to chown /dev/pts: %m");

        /* Create /dev/ptmx symlink */
        p = prefix_roota(dest, "/dev/ptmx");
        if (symlink("pts/ptmx", p) < 0)
                return log_error_errno(errno, "Failed to create /dev/ptmx symlink: %m");
        r = userns_lchown(p, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to chown /dev/ptmx: %m");

        /* And fix /dev/pts/ptmx ownership */
        p = prefix_roota(dest, "/dev/pts/ptmx");
        r = userns_lchown(p, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to chown /dev/pts/ptmx: %m");

        return 0;
}

static int setup_stdio_as_dev_console(void) {
        _cleanup_close_ int terminal = -EBADF;
        int r;

        /* We open the TTY in O_NOCTTY mode, so that we do not become controller yet. We'll do that later
         * explicitly, if we are configured to. */
        terminal = open_terminal("/dev/console", O_RDWR|O_NOCTTY);
        if (terminal < 0)
                return log_error_errno(terminal, "Failed to open console: %m");

        /* Make sure we can continue logging to the original stderr, even if
         * stderr points elsewhere now */
        r = log_dup_console();
        if (r < 0)
                return log_error_errno(r, "Failed to duplicate stderr: %m");

        /* invalidates 'terminal' on success and failure */
        r = rearrange_stdio(terminal, terminal, terminal);
        TAKE_FD(terminal);
        if (r < 0)
                return log_error_errno(r, "Failed to move console to stdin/stdout/stderr: %m");

        return 0;
}

static int setup_dev_console(const char *console) {
        _cleanup_free_ char *p = NULL;
        int r;

        /* Create /dev/console symlink */
        r = path_make_relative("/dev", console, &p);
        if (r < 0)
                return log_error_errno(r, "Failed to create relative path: %m");

        if (symlink(p, "/dev/console") < 0)
                return log_error_errno(errno, "Failed to create /dev/console symlink: %m");

        return 0;
}

static int setup_keyring(void) {
        key_serial_t keyring;

        /* Allocate a new session keyring for the container. This makes sure the keyring of the session
         * systemd-nspawn was invoked from doesn't leak into the container. Note that by default we block
         * keyctl() and request_key() anyway via seccomp so doing this operation isn't strictly necessary,
         * but in case people explicitly allow-list these system calls let's make sure we don't leak anything
         * into the container. */

        keyring = keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0);
        if (keyring == -1) {
                if (errno == ENOSYS)
                        log_debug_errno(errno, "Kernel keyring not supported, ignoring.");
                else if (ERRNO_IS_PRIVILEGE(errno))
                        log_debug_errno(errno, "Kernel keyring access prohibited, ignoring.");
                else
                        return log_error_errno(errno, "Setting up kernel keyring failed: %m");
        }

        return 0;
}

static int setup_credentials(const char *root) {
        const char *q;
        int r;

        if (arg_credentials.n_credentials == 0)
                return 0;

        r = userns_mkdir(root, "/run/host", 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/host: %m");

        r = userns_mkdir(root, "/run/host/credentials", 0700, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/host/credentials: %m");

        q = prefix_roota(root, "/run/host/credentials");
        r = mount_nofollow_verbose(LOG_ERR, NULL, q, "ramfs", MS_NOSUID|MS_NOEXEC|MS_NODEV, "mode=0700");
        if (r < 0)
                return r;

        FOREACH_ARRAY(cred, arg_credentials.credentials, arg_credentials.n_credentials) {
                _cleanup_free_ char *j = NULL;
                _cleanup_close_ int fd = -EBADF;

                j = path_join(q, cred->id);
                if (!j)
                        return log_oom();

                fd = open(j, O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC|O_NOFOLLOW, 0600);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to create credential file %s: %m", j);

                r = loop_write(fd, cred->data, cred->size);
                if (r < 0)
                        return log_error_errno(r, "Failed to write credential to file %s: %m", j);

                if (fchmod(fd, 0400) < 0)
                        return log_error_errno(errno, "Failed to adjust access mode of %s: %m", j);

                if (arg_userns_mode != USER_NAMESPACE_NO) {
                        if (fchown(fd, arg_uid_shift, arg_uid_shift) < 0)
                                return log_error_errno(errno, "Failed to adjust ownership of %s: %m", j);
                }
        }

        if (chmod(q, 0500) < 0)
                return log_error_errno(errno, "Failed to adjust access mode of %s: %m", q);

        r = userns_lchown(q, 0, 0);
        if (r < 0)
                return r;

        /* Make both mount and superblock read-only now */
        r = mount_nofollow_verbose(LOG_ERR, NULL, q, NULL, MS_REMOUNT|MS_BIND|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
        if (r < 0)
                return r;

        return mount_nofollow_verbose(LOG_ERR, NULL, q, NULL, MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV, "mode=0500");
}

static int setup_kmsg(int fd_inner_socket) {
        _cleanup_(unlink_and_freep) char *from = NULL;
        _cleanup_free_ char *fifo = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(fd_inner_socket >= 0);

        BLOCK_WITH_UMASK(0000);

        /* We create the kmsg FIFO as a temporary file in /run, but immediately delete it after bind mounting it to
         * /proc/kmsg. While FIFOs on the reading side behave very similar to /proc/kmsg, their writing side behaves
         * differently from /dev/kmsg in that writing blocks when nothing is reading. In order to avoid any problems
         * with containers deadlocking due to this we simply make /dev/kmsg unavailable to the container. */

        r = tempfn_random_child("/run", "proc-kmsg", &fifo);
        if (r < 0)
                return log_error_errno(r, "Failed to generate kmsg path: %m");

        if (mkfifo(fifo, 0600) < 0)
                return log_error_errno(errno, "mkfifo() for /run/kmsg failed: %m");

        from = TAKE_PTR(fifo);

        r = mount_nofollow_verbose(LOG_ERR, from, "/proc/kmsg", NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        fd = open(from, O_RDWR|O_NONBLOCK|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open fifo: %m");

        /* Store away the fd in the socket, so that it stays open as long as we run the child */
        r = send_one_fd(fd_inner_socket, fd, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send FIFO fd: %m");

        return 0;
}

struct ExposeArgs {
        union in_addr_union address4;
        union in_addr_union address6;
        struct FirewallContext *fw_ctx;
};

static int on_address_change(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        struct ExposeArgs *args = ASSERT_PTR(userdata);

        assert(rtnl);
        assert(m);

        (void) expose_port_execute(rtnl, &args->fw_ctx, arg_expose_ports, AF_INET, &args->address4);
        (void) expose_port_execute(rtnl, &args->fw_ctx, arg_expose_ports, AF_INET6, &args->address6);
        return 0;
}

static int setup_hostname(void) {
        int r;

        if ((arg_clone_ns_flags & CLONE_NEWUTS) == 0)
                return 0;

        r = sethostname_idempotent(arg_hostname ?: arg_machine);
        if (r < 0)
                return log_error_errno(r, "Failed to set hostname: %m");

        return 0;
}

static int setup_journal(const char *directory) {
        _cleanup_free_ char *d = NULL;
        const char *p, *q;
        sd_id128_t this_id;
        bool try;
        int r;

        /* Don't link journals in ephemeral mode */
        if (arg_ephemeral)
                return 0;

        if (arg_link_journal == LINK_NO)
                return 0;

        try = arg_link_journal_try || arg_link_journal == LINK_AUTO;

        r = sd_id128_get_machine(&this_id);
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve machine ID: %m");

        if (sd_id128_equal(arg_uuid, this_id)) {
                log_full(try ? LOG_WARNING : LOG_ERR,
                         "Host and machine ids are equal (%s): refusing to link journals", SD_ID128_TO_STRING(arg_uuid));
                if (try)
                        return 0;
                return -EEXIST;
        }

        FOREACH_STRING(dirname, "/var", "/var/log", "/var/log/journal") {
                r = userns_mkdir(directory, dirname, 0755, 0, 0);
                if (r < 0) {
                        bool ignore = r == -EROFS && try;
                        log_full_errno(ignore ? LOG_DEBUG : LOG_ERR, r,
                                       "Failed to create %s%s: %m", dirname, ignore ? ", ignoring" : "");
                        return ignore ? 0 : r;
                }
        }

        p = strjoina("/var/log/journal/", SD_ID128_TO_STRING(arg_uuid));
        q = prefix_roota(directory, p);

        if (path_is_mount_point(p, NULL, 0) > 0) {
                if (try)
                        return 0;

                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                       "%s: already a mount point, refusing to use for journal", p);
        }

        if (path_is_mount_point(q, NULL, 0) > 0) {
                if (try)
                        return 0;

                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                       "%s: already a mount point, refusing to use for journal", q);
        }

        r = readlink_and_make_absolute(p, &d);
        if (r >= 0) {
                if (IN_SET(arg_link_journal, LINK_GUEST, LINK_AUTO) &&
                    path_equal(d, q)) {

                        r = userns_mkdir(directory, p, 0755, 0, 0);
                        if (r < 0)
                                log_warning_errno(r, "Failed to create directory %s: %m", q);
                        return 0;
                }

                if (unlink(p) < 0)
                        return log_error_errno(errno, "Failed to remove symlink %s: %m", p);
        } else if (r == -EINVAL) {

                if (arg_link_journal == LINK_GUEST &&
                    rmdir(p) < 0) {

                        if (errno == ENOTDIR) {
                                log_error("%s already exists and is neither a symlink nor a directory", p);
                                return r;
                        } else
                                return log_error_errno(errno, "Failed to remove %s: %m", p);
                }
        } else if (r != -ENOENT)
                return log_error_errno(r, "readlink(%s) failed: %m", p);

        if (arg_link_journal == LINK_GUEST) {

                if (symlink(q, p) < 0) {
                        if (try) {
                                log_debug_errno(errno, "Failed to symlink %s to %s, skipping journal setup: %m", q, p);
                                return 0;
                        } else
                                return log_error_errno(errno, "Failed to symlink %s to %s: %m", q, p);
                }

                r = userns_mkdir(directory, p, 0755, 0, 0);
                if (r < 0)
                        log_warning_errno(r, "Failed to create directory %s: %m", q);
                return 0;
        }

        if (arg_link_journal == LINK_HOST) {
                /* don't create parents here — if the host doesn't have
                 * permanent journal set up, don't force it here */

                r = RET_NERRNO(mkdir(p, 0755));
                if (r < 0 && r != -EEXIST) {
                        if (try) {
                                log_debug_errno(r, "Failed to create %s, skipping journal setup: %m", p);
                                return 0;
                        } else
                                return log_error_errno(r, "Failed to create %s: %m", p);
                }

        } else if (access(p, F_OK) < 0)
                return 0;

        if (dir_is_empty(q, /* ignore_hidden_or_backup= */ false) == 0)
                log_warning("%s is not empty, proceeding anyway.", q);

        r = userns_mkdir(directory, p, 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create %s: %m", q);

        r = mount_nofollow_verbose(LOG_DEBUG, p, q, NULL, MS_BIND, NULL);
        if (r < 0)
                return log_error_errno(errno, "Failed to bind mount journal from host into guest: %m");

        return 0;
}

static int drop_capabilities(uid_t uid) {
        CapabilityQuintet q;

        /* Let's initialize all five capability sets to something valid. If the quintet was configured via
         * OCI use that, but fill in missing bits. If it wasn't then derive the quintet in full from
         * arg_caps_retain. */

        if (capability_quintet_is_set(&arg_full_capabilities)) {
                q = arg_full_capabilities;

                if (q.bounding == UINT64_MAX)
                        q.bounding = uid == 0 ? arg_caps_retain : 0;

                if (q.effective == UINT64_MAX)
                        q.effective = uid == 0 ? q.bounding : 0;

                if (q.inheritable == UINT64_MAX)
                        q.inheritable = uid == 0 ? q.bounding : arg_caps_ambient;

                if (q.permitted == UINT64_MAX)
                        q.permitted = uid == 0 ? q.bounding : arg_caps_ambient;

                if (q.ambient == UINT64_MAX && ambient_capabilities_supported())
                        q.ambient = arg_caps_ambient;

                if (capability_quintet_mangle(&q))
                        return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Cannot set capabilities that are not in the current bounding set.");

        } else {
                q = (CapabilityQuintet) {
                        .bounding = arg_caps_retain,
                        .effective = uid == 0 ? arg_caps_retain : 0,
                        .inheritable = uid == 0 ? arg_caps_retain : arg_caps_ambient,
                        .permitted = uid == 0 ? arg_caps_retain : arg_caps_ambient,
                        .ambient = ambient_capabilities_supported() ? arg_caps_ambient : UINT64_MAX,
                };

                /* If we're not using OCI, proceed with mangled capabilities (so we don't error out)
                 * in order to maintain the same behavior as systemd < 242. */
                if (capability_quintet_mangle(&q))
                        log_full(arg_quiet ? LOG_DEBUG : LOG_WARNING,
                                 "Some capabilities will not be set because they are not in the current bounding set.");

        }

        return capability_quintet_enforce(&q);
}

static int reset_audit_loginuid(void) {
        _cleanup_free_ char *p = NULL;
        int r;

        if ((arg_clone_ns_flags & CLONE_NEWPID) == 0)
                return 0;

        r = read_one_line_file("/proc/self/loginuid", &p);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to read /proc/self/loginuid: %m");

        /* Already reset? */
        if (streq(p, "4294967295"))
                return 0;

        r = write_string_file("/proc/self/loginuid", "4294967295", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0) {
                log_error_errno(r,
                                "Failed to reset audit login UID. This probably means that your kernel is too\n"
                                "old and you have audit enabled. Note that the auditing subsystem is known to\n"
                                "be incompatible with containers on old kernels. Please make sure to upgrade\n"
                                "your kernel or to off auditing with 'audit=0' on the kernel command line before\n"
                                "using systemd-nspawn. Sleeping for 5s... (%m)");

                sleep(5);
        }

        return 0;
}

static int mount_tunnel_dig(const char *root) {
        const char *p, *q;
        int r;

        (void) mkdir_p("/run/systemd/nspawn/", 0755);
        (void) mkdir_p("/run/systemd/nspawn/propagate", 0600);
        p = strjoina("/run/systemd/nspawn/propagate/", arg_machine);
        (void) mkdir_p(p, 0600);

        r = userns_mkdir(root, "/run/host", 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/host: %m");

        r = userns_mkdir(root, NSPAWN_MOUNT_TUNNEL, 0600, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create "NSPAWN_MOUNT_TUNNEL": %m");

        q = prefix_roota(root, NSPAWN_MOUNT_TUNNEL);
        r = mount_nofollow_verbose(LOG_ERR, p, q, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        r = mount_nofollow_verbose(LOG_ERR, NULL, q, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY, NULL);
        if (r < 0)
                return r;

        return 0;
}

static int mount_tunnel_open(void) {
        int r;

        r = mount_follow_verbose(LOG_ERR, NULL, NSPAWN_MOUNT_TUNNEL, NULL, MS_SLAVE, NULL);
        if (r < 0)
                return r;

        return 0;
}

static int setup_machine_id(const char *directory) {
        int r;

        /* If the UUID in the container is already set, then that's what counts, and we use. If it isn't set, and the
         * caller passed --uuid=, then we'll pass it in the $container_uuid env var to PID 1 of the container. The
         * assumption is that PID 1 will then write it to /etc/machine-id to make it persistent. If --uuid= is not
         * passed we generate a random UUID, and pass it via $container_uuid. In effect this means that /etc/machine-id
         * in the container and our idea of the container UUID will always be in sync (at least if PID 1 in the
         * container behaves nicely). */

        r = id128_get_machine(directory, &arg_uuid);
        if (ERRNO_IS_NEG_MACHINE_ID_UNSET(r)) {
                /* If the file is missing, empty, or uninitialized, we don't mind */
                if (sd_id128_is_null(arg_uuid)) {
                        r = sd_id128_randomize(&arg_uuid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to acquire randomized machine UUID: %m");
                }
        } else if (r < 0)
                return log_error_errno(r, "Failed to read machine ID from container image: %m");

        return 0;
}

static int recursive_chown(const char *directory, uid_t shift, uid_t range) {
        int r;

        assert(directory);

        if (arg_userns_mode == USER_NAMESPACE_NO || arg_userns_ownership != USER_NAMESPACE_OWNERSHIP_CHOWN)
                return 0;

        r = path_patch_uid(directory, arg_uid_shift, arg_uid_range);
        if (r == -EOPNOTSUPP)
                return log_error_errno(r, "Automatic UID/GID adjusting is only supported for UID/GID ranges starting at multiples of 2^16 with a range of 2^16.");
        if (r == -EBADE)
                return log_error_errno(r, "Upper 16 bits of root directory UID and GID do not match.");
        if (r < 0)
                return log_error_errno(r, "Failed to adjust UID/GID shift of OS tree: %m");
        if (r == 0)
                log_debug("Root directory of image is already owned by the right UID/GID range, skipping recursive chown operation.");
        else
                log_debug("Patched directory tree to match UID/GID range.");

        return r;
}

/*
 * Return values:
 * < 0 : wait_for_terminate() failed to get the state of the
 *       container, the container was terminated by a signal, or
 *       failed for an unknown reason.  No change is made to the
 *       container argument.
 * > 0 : The program executed in the container terminated with an
 *       error.  The exit code of the program executed in the
 *       container is returned.  The container argument has been set
 *       to CONTAINER_TERMINATED.
 *   0 : The container is being rebooted, has been shut down or exited
 *       successfully.  The container argument has been set to either
 *       CONTAINER_TERMINATED or CONTAINER_REBOOTED.
 *
 * That is, success is indicated by a return value of zero, and an
 * error is indicated by a non-zero value.
 */
static int wait_for_container(pid_t pid, ContainerStatus *container) {
        siginfo_t status;
        int r;

        r = wait_for_terminate(pid, &status);
        if (r < 0)
                return log_warning_errno(r, "Failed to wait for container: %m");

        switch (status.si_code) {

        case CLD_EXITED:
                if (status.si_status == 0)
                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "Container %s exited successfully.", arg_machine);
                else
                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "Container %s failed with error code %i.", arg_machine, status.si_status);

                *container = CONTAINER_TERMINATED;
                return status.si_status;

        case CLD_KILLED:
                if (status.si_status == SIGINT) {
                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "Container %s has been shut down.", arg_machine);
                        *container = CONTAINER_TERMINATED;
                        return 0;

                } else if (status.si_status == SIGHUP) {
                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "Container %s is being rebooted.", arg_machine);
                        *container = CONTAINER_REBOOTED;
                        return 0;
                }

                _fallthrough_;
        case CLD_DUMPED:
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Container %s terminated by signal %s.", arg_machine, signal_to_string(status.si_status));

        default:
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Container %s failed due to unknown reason.", arg_machine);
        }
}

static int on_orderly_shutdown(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        pid_t pid;

        pid = PTR_TO_PID(userdata);
        if (pid > 0) {
                if (kill(pid, arg_kill_signal) >= 0) {
                        log_info("Trying to halt container. Send SIGTERM again to trigger immediate termination.");
                        sd_event_source_set_userdata(s, NULL);
                        return 0;
                }
        }

        sd_event_exit(sd_event_source_get_event(s), 0);
        return 0;
}

static int on_sigchld(sd_event_source *s, const struct signalfd_siginfo *ssi, void *userdata) {
        pid_t pid;

        assert(s);
        assert(ssi);

        pid = PTR_TO_PID(userdata);

        for (;;) {
                siginfo_t si = {};

                if (waitid(P_ALL, 0, &si, WNOHANG|WNOWAIT|WEXITED) < 0)
                        return log_error_errno(errno, "Failed to waitid(): %m");
                if (si.si_pid == 0) /* No pending children. */
                        break;
                if (si.si_pid == pid) {
                        /* The main process we care for has exited. Return from
                         * signal handler but leave the zombie. */
                        sd_event_exit(sd_event_source_get_event(s), 0);
                        break;
                }

                /* Reap all other children. */
                (void) waitid(P_PID, si.si_pid, &si, WNOHANG|WEXITED);
        }

        return 0;
}

static int on_request_stop(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        pid_t pid;

        assert(m);

        pid = PTR_TO_PID(userdata);

        if (arg_kill_signal > 0) {
                log_info("Container termination requested. Attempting to halt container.");
                (void) kill(pid, arg_kill_signal);
        } else {
                log_info("Container termination requested. Exiting.");
                sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), 0);
        }

        return 0;
}

static int determine_names(void) {
        int r;

        if (arg_template && !arg_directory && arg_machine) {

                /* If --template= was specified then we should not
                 * search for a machine, but instead create a new one
                 * in /var/lib/machine. */

                arg_directory = path_join("/var/lib/machines", arg_machine);
                if (!arg_directory)
                        return log_oom();
        }

        if (!arg_image && !arg_directory) {
                if (arg_machine) {
                        _cleanup_(image_unrefp) Image *i = NULL;

                        r = image_find(IMAGE_MACHINE, arg_machine, NULL, &i);
                        if (r == -ENOENT)
                                return log_error_errno(r, "No image for machine '%s'.", arg_machine);
                        if (r < 0)
                                return log_error_errno(r, "Failed to find image for machine '%s': %m", arg_machine);

                        if (IN_SET(i->type, IMAGE_RAW, IMAGE_BLOCK))
                                r = free_and_strdup(&arg_image, i->path);
                        else
                                r = free_and_strdup(&arg_directory, i->path);
                        if (r < 0)
                                return log_oom();

                        if (!arg_ephemeral)
                                arg_read_only = arg_read_only || i->read_only;
                } else {
                        r = safe_getcwd(&arg_directory);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine current directory: %m");
                }

                if (!arg_directory && !arg_image)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine path, please use -D or -i.");
        }

        if (!arg_machine) {
                if (arg_directory && path_equal(arg_directory, "/"))
                        arg_machine = gethostname_malloc();
                else if (arg_image) {
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

                hostname_cleanup(arg_machine);
                if (!hostname_is_valid(arg_machine, 0))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine machine name automatically, please use -M.");

                /* Copy the machine name before the random suffix is added below, otherwise we won't be able
                 * to match fixed config file names. */
                arg_settings_filename = strjoin(arg_machine, ".nspawn");
                if (!arg_settings_filename)
                        return log_oom();

                /* Add a random suffix when this is an ephemeral machine, so that we can run many
                 * instances at once without manually having to specify -M each time. */
                if (arg_ephemeral)
                        if (strextendf(&arg_machine, "-%016" PRIx64, random_u64()) < 0)
                                return log_oom();
        } else {
                arg_settings_filename = strjoin(arg_machine, ".nspawn");
                if (!arg_settings_filename)
                        return log_oom();
        }

        return 0;
}

static int chase_and_update(char **p, unsigned flags) {
        char *chased;
        int r;

        assert(p);

        if (!*p)
                return 0;

        r = chase(*p, NULL, flags, &chased, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve path %s: %m", *p);

        return free_and_replace(*p, chased);
}

static int determine_uid_shift(const char *directory) {

        if (arg_userns_mode == USER_NAMESPACE_NO) {
                arg_uid_shift = 0;
                return 0;
        }

        if (arg_uid_shift == UID_INVALID) {
                struct stat st;

                /* Read the UID shift off the image. Maybe we can reuse this to avoid chowning. */

                if (stat(directory, &st) < 0)
                        return log_error_errno(errno, "Failed to determine UID base of %s: %m", directory);

                arg_uid_shift = st.st_uid & UINT32_C(0xffff0000);

                if (arg_uid_shift != (st.st_gid & UINT32_C(0xffff0000)))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "UID and GID base of %s don't match.", directory);

                arg_uid_range = UINT32_C(0x10000);

                if (arg_uid_shift != 0) {
                        /* If the image is shifted already, then we'll fall back to classic chowning, for
                         * compatibility (and simplicity), or refuse if mapping is explicitly requested.  */

                        if (arg_userns_ownership == USER_NAMESPACE_OWNERSHIP_AUTO) {
                                log_debug("UID base of %s is non-zero, not using UID mapping.", directory);
                                arg_userns_ownership = USER_NAMESPACE_OWNERSHIP_CHOWN;
                        } else if (arg_userns_ownership == USER_NAMESPACE_OWNERSHIP_MAP)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "UID base of %s is not zero, UID mapping not supported.", directory);
                }
        }

        if (!userns_shift_range_valid(arg_uid_shift, arg_uid_range))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "UID base too high for UID range.");

        return 0;
}

static unsigned long effective_clone_ns_flags(void) {
        unsigned long flags = arg_clone_ns_flags;

        if (arg_private_network)
                flags |= CLONE_NEWNET;
        if (arg_use_cgns)
                flags |= CLONE_NEWCGROUP;
        if (arg_userns_mode != USER_NAMESPACE_NO)
                flags |= CLONE_NEWUSER;

        return flags;
}

static int patch_sysctl(void) {

        /* This table is inspired by runc's sysctl() function */
        static const struct {
                const char *key;
                bool prefix;
                unsigned long clone_flags;
        } safe_sysctl[] = {
                { "kernel.hostname",   false, CLONE_NEWUTS },
                { "kernel.domainname", false, CLONE_NEWUTS },
                { "kernel.msgmax",     false, CLONE_NEWIPC },
                { "kernel.msgmnb",     false, CLONE_NEWIPC },
                { "kernel.msgmni",     false, CLONE_NEWIPC },
                { "kernel.sem",        false, CLONE_NEWIPC },
                { "kernel.shmall",     false, CLONE_NEWIPC },
                { "kernel.shmmax",     false, CLONE_NEWIPC },
                { "kernel.shmmni",     false, CLONE_NEWIPC },
                { "fs.mqueue.",        true,  CLONE_NEWIPC },
                { "net.",              true,  CLONE_NEWNET },
        };

        unsigned long flags;
        int r;

        flags = effective_clone_ns_flags();

        STRV_FOREACH_PAIR(k, v, arg_sysctl) {
                bool good = false;
                size_t i;

                for (i = 0; i < ELEMENTSOF(safe_sysctl); i++) {

                        if (!FLAGS_SET(flags, safe_sysctl[i].clone_flags))
                                continue;

                        if (safe_sysctl[i].prefix)
                                good = startswith(*k, safe_sysctl[i].key);
                        else
                                good = streq(*k, safe_sysctl[i].key);

                        if (good)
                                break;
                }

                if (!good)
                        return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Refusing to write to sysctl '%s', as it is not safe in the selected namespaces.", *k);

                r = sysctl_write(*k, *v);
                if (r < 0)
                        return log_error_errno(r, "Failed to write sysctl '%s': %m", *k);
        }

        return 0;
}

static int inner_child(
                Barrier *barrier,
                int fd_inner_socket,
                FDSet *fds,
                char **os_release_pairs) {

        _cleanup_free_ char *home = NULL;
        size_t n_env = 1;
        char *envp[] = {
                (char*) "PATH=" DEFAULT_PATH_COMPAT,
                NULL, /* container */
                NULL, /* TERM */
                NULL, /* HOME */
                NULL, /* USER */
                NULL, /* LOGNAME */
                NULL, /* container_uuid */
                NULL, /* LISTEN_FDS */
                NULL, /* LISTEN_PID */
                NULL, /* NOTIFY_SOCKET */
                NULL, /* CREDENTIALS_DIRECTORY */
                NULL, /* LANG */
                NULL
        };
        const char *exec_target;
        _cleanup_strv_free_ char **env_use = NULL;
        int r, which_failed;

        /* This is the "inner" child process, i.e. the one forked off by the "outer" child process, which is the one
         * the container manager itself forked off. At the time of clone() it gained its own CLONE_NEWNS, CLONE_NEWPID,
         * CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER namespaces. Note that it has its own CLONE_NEWNS namespace,
         * separate from the CLONE_NEWNS created for the "outer" child, and also separate from the host's CLONE_NEWNS
         * namespace. The reason for having two levels of CLONE_NEWNS namespaces is that the "inner" one is owned by
         * the CLONE_NEWUSER namespace of the container, while the "outer" one is owned by the host's CLONE_NEWUSER
         * namespace.
         *
         * Note at this point we have no CLONE_NEWNET namespace yet. We'll acquire that one later through
         * unshare(). See below. */

        assert(barrier);
        assert(fd_inner_socket >= 0);

        log_debug("Inner child is initializing.");

        if (arg_userns_mode != USER_NAMESPACE_NO) {
                /* Tell the parent, that it now can write the UID map. */
                (void) barrier_place(barrier); /* #1 */

                /* Wait until the parent wrote the UID map */
                if (!barrier_place_and_sync(barrier)) /* #2 */
                        return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "Parent died too early");

                /* Become the new root user inside our namespace */
                r = reset_uid_gid();
                if (r < 0)
                        return log_error_errno(r, "Couldn't become new root: %m");

                /* Creating a new user namespace means all MS_SHARED mounts become MS_SLAVE. Let's put them
                 * back to MS_SHARED here, since that's what we want as defaults. (This will not reconnect
                 * propagation, but simply create new peer groups for all our mounts). */
                r = mount_follow_verbose(LOG_ERR, NULL, "/", NULL, MS_SHARED|MS_REC, NULL);
                if (r < 0)
                        return r;
        }

        r = mount_all(NULL,
                      arg_mount_settings | MOUNT_IN_USERNS,
                      arg_uid_shift,
                      arg_selinux_apifs_context);
        if (r < 0)
                return r;

        if (!arg_network_namespace_path && arg_private_network) {
                r = unshare(CLONE_NEWNET);
                if (r < 0)
                        return log_error_errno(errno, "Failed to unshare network namespace: %m");

                /* Tell the parent that it can setup network interfaces. */
                (void) barrier_place(barrier); /* #3 */
        }

        r = mount_sysfs(NULL, arg_mount_settings);
        if (r < 0)
                return r;

        /* Wait until we are cgroup-ified, so that we
         * can mount the right cgroup path writable */
        if (!barrier_place_and_sync(barrier)) /* #4 */
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH),
                                       "Parent died too early");

        if (arg_use_cgns) {
                r = unshare(CLONE_NEWCGROUP);
                if (r < 0)
                        return log_error_errno(errno, "Failed to unshare cgroup namespace: %m");
                r = mount_cgroups(
                                "",
                                arg_unified_cgroup_hierarchy,
                                arg_userns_mode != USER_NAMESPACE_NO,
                                arg_uid_shift,
                                arg_uid_range,
                                arg_selinux_apifs_context,
                                true);
        } else
                r = mount_systemd_cgroup_writable("", arg_unified_cgroup_hierarchy);
        if (r < 0)
                return r;

        r = setup_boot_id();
        if (r < 0)
                return r;

        r = setup_kmsg(fd_inner_socket);
        if (r < 0)
                return r;

        r = mount_custom(
                        "/",
                        arg_custom_mounts,
                        arg_n_custom_mounts,
                        0,
                        0,
                        arg_selinux_apifs_context,
                        MOUNT_NON_ROOT_ONLY | MOUNT_IN_USERNS);
        if (r < 0)
                return r;

        if (setsid() < 0)
                return log_error_errno(errno, "setsid() failed: %m");

        if (arg_private_network)
                (void) loopback_setup();

        if (arg_expose_ports) {
                r = expose_port_send_rtnl(fd_inner_socket);
                if (r < 0)
                        return r;
        }

        if (arg_console_mode != CONSOLE_PIPE) {
                _cleanup_close_ int master = -EBADF;
                _cleanup_free_ char *console = NULL;

                /* Allocate a pty and make it available as /dev/console. */
                master = openpt_allocate(O_RDWR|O_NONBLOCK, &console);
                if (master < 0)
                        return log_error_errno(master, "Failed to allocate a pty: %m");

                r = setup_dev_console(console);
                if (r < 0)
                        return log_error_errno(r, "Failed to set up /dev/console: %m");

                r = send_one_fd(fd_inner_socket, master, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to send master fd: %m");

                r = setup_stdio_as_dev_console();
                if (r < 0)
                        return r;
        }

        r = patch_sysctl();
        if (r < 0)
                return r;

        if (arg_oom_score_adjust_set) {
                r = set_oom_score_adjust(arg_oom_score_adjust);
                if (r < 0)
                        return log_error_errno(r, "Failed to adjust OOM score: %m");
        }

        if (arg_cpu_set.set)
                if (sched_setaffinity(0, arg_cpu_set.allocated, arg_cpu_set.set) < 0)
                        return log_error_errno(errno, "Failed to set CPU affinity: %m");

        (void) setup_hostname();

        if (arg_personality != PERSONALITY_INVALID) {
                r = safe_personality(arg_personality);
                if (r < 0)
                        return log_error_errno(r, "personality() failed: %m");
#ifdef ARCHITECTURE_SECONDARY
        } else if (arg_architecture == ARCHITECTURE_SECONDARY) {
                r = safe_personality(PER_LINUX32);
                if (r < 0)
                        return log_error_errno(r, "personality() failed: %m");
#endif
        } else if (!arg_quiet && arg_architecture >= 0 && arg_architecture != native_architecture())
                log_notice("Selected architecture '%s' not supported natively on the local CPU, assuming "
                           "invocation with qemu userspace emulator (or equivalent) in effect.",
                           architecture_to_string(arg_architecture));

        r = setrlimit_closest_all((const struct rlimit *const*) arg_rlimit, &which_failed);
        if (r < 0)
                return log_error_errno(r, "Failed to apply resource limit RLIMIT_%s: %m", rlimit_to_string(which_failed));

#if HAVE_SECCOMP
        if (arg_seccomp) {

                if (is_seccomp_available()) {
                        r = seccomp_load(arg_seccomp);
                        if (ERRNO_IS_NEG_SECCOMP_FATAL(r))
                                return log_error_errno(r, "Failed to install seccomp filter: %m");
                        if (r < 0)
                                log_debug_errno(r, "Failed to install seccomp filter: %m");
                }
        } else
#endif
        {
                r = setup_seccomp(arg_caps_retain, arg_syscall_allow_list, arg_syscall_deny_list);
                if (r < 0)
                        return r;
        }

        if (arg_suppress_sync) {
#if HAVE_SECCOMP
                r = seccomp_suppress_sync();
                if (r < 0)
                        log_debug_errno(r, "Failed to install sync() suppression seccomp filter, ignoring: %m");
#else
                log_debug("systemd is built without SECCOMP support. Ignoring --suppress-sync= command line option and SuppressSync= setting.");
#endif
        }

#if HAVE_SELINUX
        if (arg_selinux_context)
                if (setexeccon(arg_selinux_context) < 0)
                        return log_error_errno(errno, "setexeccon(\"%s\") failed: %m", arg_selinux_context);
#endif

        /* Make sure we keep the caps across the uid/gid dropping, so that we can retain some selected caps
         * if we need to later on. */
        if (prctl(PR_SET_KEEPCAPS, 1) < 0)
                return log_error_errno(errno, "Failed to set PR_SET_KEEPCAPS: %m");

        if (uid_is_valid(arg_uid) || gid_is_valid(arg_gid))
                r = change_uid_gid_raw(arg_uid, arg_gid, arg_supplementary_gids, arg_n_supplementary_gids, arg_console_mode != CONSOLE_PIPE);
        else
                r = change_uid_gid(arg_user, arg_console_mode != CONSOLE_PIPE, &home);
        if (r < 0)
                return r;

        r = drop_capabilities(getuid());
        if (r < 0)
                return log_error_errno(r, "Dropping capabilities failed: %m");

        if (arg_no_new_privileges)
                if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
                        return log_error_errno(errno, "Failed to disable new privileges: %m");

        /* LXC sets container=lxc, so follow the scheme here */
        envp[n_env++] = strjoina("container=", arg_container_service_name);

        envp[n_env] = strv_find_prefix(environ, "TERM=");
        if (envp[n_env])
                n_env++;

        if (home || !uid_is_valid(arg_uid) || arg_uid == 0)
                if (asprintf(envp + n_env++, "HOME=%s", home ?: "/root") < 0)
                        return log_oom();

        if (arg_user || !uid_is_valid(arg_uid) || arg_uid == 0)
                if (asprintf(envp + n_env++, "USER=%s", arg_user ?: "root") < 0 ||
                    asprintf(envp + n_env++, "LOGNAME=%s", arg_user ?: "root") < 0)
                        return log_oom();

        assert(!sd_id128_is_null(arg_uuid));

        if (asprintf(envp + n_env++, "container_uuid=%s", SD_ID128_TO_UUID_STRING(arg_uuid)) < 0)
                return log_oom();

        if (fdset_size(fds) > 0) {
                r = fdset_cloexec(fds, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to unset O_CLOEXEC for file descriptors.");

                if ((asprintf(envp + n_env++, "LISTEN_FDS=%u", fdset_size(fds)) < 0) ||
                    (asprintf(envp + n_env++, "LISTEN_PID=1") < 0))
                        return log_oom();
        }
        if (asprintf(envp + n_env++, "NOTIFY_SOCKET=%s", NSPAWN_NOTIFY_SOCKET_PATH) < 0)
                return log_oom();

        if (arg_credentials.n_credentials > 0) {
                envp[n_env] = strdup("CREDENTIALS_DIRECTORY=/run/host/credentials");
                if (!envp[n_env])
                        return log_oom();
                n_env++;
        }

        if (arg_start_mode != START_BOOT) {
                envp[n_env] = strdup("LANG=" SYSTEMD_NSPAWN_LOCALE);
                if (!envp[n_env])
                        return log_oom();
                n_env++;
        }

        env_use = strv_env_merge(envp, os_release_pairs, arg_setenv);
        if (!env_use)
                return log_oom();

        /* Let the parent know that we are ready and wait until the parent is ready with the setup, too... */
        if (!barrier_place_and_sync(barrier)) /* #5 */
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "Parent died too early");

        if (arg_chdir)
                if (chdir(arg_chdir) < 0)
                        return log_error_errno(errno, "Failed to change to specified working directory %s: %m", arg_chdir);

        if (arg_start_mode == START_PID2) {
                r = stub_pid1(arg_uuid);
                if (r < 0)
                        return r;
        }

        if (arg_console_mode != CONSOLE_PIPE) {
                /* So far our pty wasn't controlled by any process. Finally, it's time to change that, if we
                 * are configured for that. Acquire it as controlling tty. */
                if (ioctl(STDIN_FILENO, TIOCSCTTY) < 0)
                        return log_error_errno(errno, "Failed to acquire controlling TTY: %m");
        }

        log_debug("Inner child completed, invoking payload.");

        /* Now, explicitly close the log, so that we then can close all remaining fds. Closing the log explicitly first
         * has the benefit that the logging subsystem knows about it, and is thus ready to be reopened should we need
         * it again. Note that the other fds closed here are at least the locking and barrier fds. */
        log_close();
        log_set_open_when_needed(true);
        log_settle_target();

        (void) fdset_close_others(fds);

        if (arg_start_mode == START_BOOT) {
                char **a;
                size_t m;

                /* Automatically search for the init system */

                m = strv_length(arg_parameters);
                a = newa(char*, m + 2);
                memcpy_safe(a + 1, arg_parameters, m * sizeof(char*));
                a[1 + m] = NULL;

                FOREACH_STRING(init,
                               "/usr/lib/systemd/systemd",
                               "/lib/systemd/systemd",
                               "/sbin/init") {
                        a[0] = (char*) init;
                        execve(a[0], a, env_use);
                }

                exec_target = "/usr/lib/systemd/systemd, /lib/systemd/systemd, /sbin/init";
        } else if (!strv_isempty(arg_parameters)) {
                const char *dollar_path;

                exec_target = arg_parameters[0];

                /* Use the user supplied search $PATH if there is one, or DEFAULT_PATH_COMPAT if not to search the
                 * binary. */
                dollar_path = strv_env_get(env_use, "PATH");
                if (dollar_path) {
                        if (setenv("PATH", dollar_path, 1) < 0)
                                return log_error_errno(errno, "Failed to update $PATH: %m");
                }

                execvpe(arg_parameters[0], arg_parameters, env_use);
        } else {
                if (!arg_chdir)
                        /* If we cannot change the directory, we'll end up in /, that is expected. */
                        (void) chdir(home ?: "/root");

                execle(DEFAULT_USER_SHELL, "-" DEFAULT_USER_SHELL_NAME, NULL, env_use);
                if (!streq(DEFAULT_USER_SHELL, "/bin/bash"))
                        execle("/bin/bash", "-bash", NULL, env_use);
                if (!streq(DEFAULT_USER_SHELL, "/bin/sh"))
                        execle("/bin/sh", "-sh", NULL, env_use);

                exec_target = DEFAULT_USER_SHELL ", /bin/bash, /bin/sh";
        }

        return log_error_errno(errno, "execv(%s) failed: %m", exec_target);
}

static int setup_notify_child(void) {
        _cleanup_close_ int fd = -EBADF;
        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = NSPAWN_NOTIFY_SOCKET_PATH,
        };
        int r;

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to allocate notification socket: %m");

        (void) mkdir_parents(NSPAWN_NOTIFY_SOCKET_PATH, 0755);
        (void) sockaddr_un_unlink(&sa.un);

        r = bind(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un));
        if (r < 0)
                return log_error_errno(errno, "bind(" NSPAWN_NOTIFY_SOCKET_PATH ") failed: %m");

        r = userns_lchown(NSPAWN_NOTIFY_SOCKET_PATH, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to chown " NSPAWN_NOTIFY_SOCKET_PATH ": %m");

        r = setsockopt_int(fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_error_errno(r, "SO_PASSCRED failed: %m");

        return TAKE_FD(fd);
}

static int outer_child(
                Barrier *barrier,
                const char *directory,
                DissectedImage *dissected_image,
                int fd_outer_socket,
                int fd_inner_socket,
                FDSet *fds,
                int netns_fd) {

        _cleanup_(bind_user_context_freep) BindUserContext *bind_user_context = NULL;
        _cleanup_strv_free_ char **os_release_pairs = NULL;
        _cleanup_close_ int fd = -EBADF, mntns_fd = -EBADF;
        bool idmap = false;
        const char *p;
        pid_t pid;
        ssize_t l;
        int r;

        /* This is the "outer" child process, i.e the one forked off by the container manager itself. It
         * already has its own CLONE_NEWNS namespace (which was created by the clone()). It still lives in
         * the host's CLONE_NEWPID, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER and CLONE_NEWNET
         * namespaces. After it completed a number of initializations a second child (the "inner" one) is
         * forked off it, and it exits. */

        assert(barrier);
        assert(directory);
        assert(fd_outer_socket >= 0);
        assert(fd_inner_socket >= 0);

        log_debug("Outer child is initializing.");

        r = load_os_release_pairs_with_prefix("/", "container_host_", &os_release_pairs);
        if (r < 0)
                log_debug_errno(r, "Failed to read os-release from host for container, ignoring: %m");

        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
                return log_error_errno(errno, "PR_SET_PDEATHSIG failed: %m");

        r = reset_audit_loginuid();
        if (r < 0)
                return r;

        /* Mark everything as slave, so that we still receive mounts from the real root, but don't propagate
         * mounts to the real root. */
        r = mount_follow_verbose(LOG_ERR, NULL, "/", NULL, MS_SLAVE|MS_REC, NULL);
        if (r < 0)
                return r;

        if (dissected_image) {
                /* If we are operating on a disk image, then mount its root directory now, but leave out the
                 * rest. We can read the UID shift from it if we need to. Further down we'll mount the rest,
                 * but then with the uid shift known. That way we can mount VFAT file systems shifted to the
                 * right place right away. This makes sure ESP partitions and userns are compatible. */

                r = dissected_image_mount_and_warn(
                                dissected_image,
                                directory,
                                arg_uid_shift,
                                arg_uid_range,
                                /* userns_fd= */ -EBADF,
                                DISSECT_IMAGE_MOUNT_ROOT_ONLY|
                                DISSECT_IMAGE_DISCARD_ON_LOOP|
                                DISSECT_IMAGE_USR_NO_ROOT|
                                (arg_read_only ? DISSECT_IMAGE_READ_ONLY : DISSECT_IMAGE_FSCK|DISSECT_IMAGE_GROWFS)|
                                (arg_start_mode == START_BOOT ? DISSECT_IMAGE_VALIDATE_OS : 0));
                if (r < 0)
                        return r;
        }

        r = determine_uid_shift(directory);
        if (r < 0)
                return r;

        if (arg_userns_mode != USER_NAMESPACE_NO) {
                r = namespace_open(0, NULL, &mntns_fd, NULL, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to pin outer mount namespace: %m");

                l = send_one_fd(fd_outer_socket, mntns_fd, 0);
                if (l < 0)
                        return log_error_errno(l, "Failed to send outer mount namespace fd: %m");
                mntns_fd = safe_close(mntns_fd);

                /* Let the parent know which UID shift we read from the image */
                l = send(fd_outer_socket, &arg_uid_shift, sizeof(arg_uid_shift), MSG_NOSIGNAL);
                if (l < 0)
                        return log_error_errno(errno, "Failed to send UID shift: %m");
                if (l != sizeof(arg_uid_shift))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Short write while sending UID shift.");

                if (arg_userns_mode == USER_NAMESPACE_PICK) {
                        /* When we are supposed to pick the UID shift, the parent will check now whether the
                         * UID shift we just read from the image is available. If yes, it will send the UID
                         * shift back to us, if not it will pick a different one, and send it back to us. */

                        l = recv(fd_outer_socket, &arg_uid_shift, sizeof(arg_uid_shift), 0);
                        if (l < 0)
                                return log_error_errno(errno, "Failed to recv UID shift: %m");
                        if (l != sizeof(arg_uid_shift))
                                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                                       "Short read while receiving UID shift.");
                }

                log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                         "Selected user namespace base " UID_FMT " and range " UID_FMT ".", arg_uid_shift, arg_uid_range);
        }

        if (path_equal(directory, "/")) {
                /* If the directory we shall boot is the host, let's operate on a bind mount at a different
                 * place, so that we can make changes to its mount structure (for example, to implement
                 * --volatile=) without this interfering with our ability to access files such as
                 * /etc/localtime to copy into the container. Note that we use a fixed place for this
                 * (instead of a temporary directory, since we are living in our own mount namespace here
                 * already, and thus don't need to be afraid of colliding with anyone else's mounts). */
                (void) mkdir_p("/run/systemd/nspawn-root", 0755);

                r = mount_nofollow_verbose(LOG_ERR, "/", "/run/systemd/nspawn-root", NULL, MS_BIND|MS_REC, NULL);
                if (r < 0)
                        return r;

                directory = "/run/systemd/nspawn-root";
        }

        /* Make sure we always have a mount that we can move to root later on. */
        r = make_mount_point(directory);
        if (r < 0)
                return r;

        /* So the whole tree is now MS_SLAVE, i.e. we'll still receive mount/umount events from the host
         * mount namespace. For the directory we are going to run our container let's turn this off, so that
         * we'll live in our own little world from now on, and propagation from the host may only happen via
         * the mount tunnel dir, or not at all. */
        r = mount_follow_verbose(LOG_ERR, NULL, directory, NULL, MS_PRIVATE|MS_REC, NULL);
        if (r < 0)
                return r;

        r = setup_pivot_root(
                        directory,
                        arg_pivot_root_new,
                        arg_pivot_root_old);
        if (r < 0)
                return r;

        r = setup_volatile_mode(
                        directory,
                        arg_volatile_mode,
                        arg_uid_shift,
                        arg_selinux_apifs_context);
        if (r < 0)
                return r;

        r = bind_user_prepare(
                        directory,
                        arg_bind_user,
                        arg_uid_shift,
                        arg_uid_range,
                        &arg_custom_mounts, &arg_n_custom_mounts,
                        &bind_user_context);
        if (r < 0)
                return r;

        if (arg_userns_mode != USER_NAMESPACE_NO && bind_user_context) {
                /* Send the user maps we determined to the parent, so that it installs it in our user
                 * namespace UID map table */

                for (size_t i = 0; i < bind_user_context->n_data; i++)  {
                        uid_t map[] = {
                                bind_user_context->data[i].payload_user->uid,
                                bind_user_context->data[i].host_user->uid,
                                (uid_t) bind_user_context->data[i].payload_group->gid,
                                (uid_t) bind_user_context->data[i].host_group->gid,
                        };

                        l = send(fd_outer_socket, map, sizeof(map), MSG_NOSIGNAL);
                        if (l < 0)
                                return log_error_errno(errno, "Failed to send user UID map: %m");
                        if (l != sizeof(map))
                                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                                       "Short write while sending user UID map.");
                }
        }

        r = mount_custom(
                        directory,
                        arg_custom_mounts,
                        arg_n_custom_mounts,
                        arg_uid_shift,
                        arg_uid_range,
                        arg_selinux_apifs_context,
                        MOUNT_ROOT_ONLY);
        if (r < 0)
                return r;

        if (arg_userns_mode != USER_NAMESPACE_NO &&
            IN_SET(arg_userns_ownership, USER_NAMESPACE_OWNERSHIP_MAP, USER_NAMESPACE_OWNERSHIP_AUTO) &&
            arg_uid_shift != 0) {
                _cleanup_free_ char *usr_subtree = NULL;
                char *dirs[3];
                size_t i = 0;

                dirs[i++] = (char*) directory;

                if (dissected_image && dissected_image->partitions[PARTITION_USR].found) {
                        usr_subtree = path_join(directory, "/usr");
                        if (!usr_subtree)
                                return log_oom();

                        dirs[i++] = usr_subtree;
                }

                dirs[i] = NULL;

                r = remount_idmap(dirs, arg_uid_shift, arg_uid_range, UID_INVALID, REMOUNT_IDMAPPING_HOST_ROOT);
                if (r == -EINVAL || ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                        /* This might fail because the kernel or file system doesn't support idmapping. We
                         * can't really distinguish this nicely, nor do we have any guarantees about the
                         * error codes we see, could be EOPNOTSUPP or EINVAL. */
                        if (arg_userns_ownership != USER_NAMESPACE_OWNERSHIP_AUTO)
                                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                                       "ID mapped mounts are apparently not available, sorry.");

                        log_debug("ID mapped mounts are apparently not available on this kernel or for the selected file system, reverting to recursive chown()ing.");
                        arg_userns_ownership = USER_NAMESPACE_OWNERSHIP_CHOWN;
                } else if (r < 0)
                        return log_error_errno(r, "Failed to set up ID mapped mounts: %m");
                else {
                        log_debug("ID mapped mounts available, making use of them.");
                        idmap = true;
                }
        }

        if (dissected_image) {
                /* Now we know the uid shift, let's now mount everything else that might be in the image. */
                r = dissected_image_mount(
                                dissected_image,
                                directory,
                                arg_uid_shift,
                                arg_uid_range,
                                /* userns_fd= */ -EBADF,
                                DISSECT_IMAGE_MOUNT_NON_ROOT_ONLY|
                                DISSECT_IMAGE_DISCARD_ON_LOOP|
                                DISSECT_IMAGE_USR_NO_ROOT|
                                (arg_read_only ? DISSECT_IMAGE_READ_ONLY : DISSECT_IMAGE_FSCK|DISSECT_IMAGE_GROWFS)|
                                (idmap ? DISSECT_IMAGE_MOUNT_IDMAPPED : 0));
                if (r == -EUCLEAN)
                        return log_error_errno(r, "File system check for image failed: %m");
                if (r < 0)
                        return log_error_errno(r, "Failed to mount image file system: %m");
        }

        if (arg_unified_cgroup_hierarchy == CGROUP_UNIFIED_UNKNOWN) {
                /* OK, we don't know yet which cgroup mode to use yet. Let's figure it out, and tell the parent. */

                r = detect_unified_cgroup_hierarchy_from_image(directory);
                if (r < 0)
                        return r;

                l = send(fd_outer_socket, &arg_unified_cgroup_hierarchy, sizeof(arg_unified_cgroup_hierarchy), MSG_NOSIGNAL);
                if (l < 0)
                        return log_error_errno(errno, "Failed to send cgroup mode: %m");
                if (l != sizeof(arg_unified_cgroup_hierarchy))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Short write while sending cgroup mode.");
        }

        r = recursive_chown(directory, arg_uid_shift, arg_uid_range);
        if (r < 0)
                return r;

        r = base_filesystem_create(directory, arg_uid_shift, (gid_t) arg_uid_shift);
        if (r < 0)
                return r;

        if (arg_read_only && arg_volatile_mode == VOLATILE_NO &&
                !has_custom_root_mount(arg_custom_mounts, arg_n_custom_mounts)) {
                r = bind_remount_recursive(directory, MS_RDONLY, MS_RDONLY, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to make tree read-only: %m");
        }

        r = mount_all(directory,
                      arg_mount_settings,
                      arg_uid_shift,
                      arg_selinux_apifs_context);
        if (r < 0)
                return r;

        r = copy_devnodes(directory);
        if (r < 0)
                return r;

        r = make_extra_nodes(directory);
        if (r < 0)
                return r;

        (void) dev_setup(directory, arg_uid_shift, arg_uid_shift);

        p = prefix_roota(directory, "/run/host");
        (void) make_inaccessible_nodes(p, arg_uid_shift, arg_uid_shift);

        r = setup_pts(directory);
        if (r < 0)
                return r;

        r = mount_tunnel_dig(directory);
        if (r < 0)
                return r;

        r = setup_keyring();
        if (r < 0)
                return r;

        r = setup_credentials(directory);
        if (r < 0)
                return r;

        r = bind_user_setup(bind_user_context, directory);
        if (r < 0)
                return r;

        r = mount_custom(
                        directory,
                        arg_custom_mounts,
                        arg_n_custom_mounts,
                        arg_uid_shift,
                        arg_uid_range,
                        arg_selinux_apifs_context,
                        MOUNT_NON_ROOT_ONLY);
        if (r < 0)
                return r;

        r = setup_timezone(directory);
        if (r < 0)
                return r;

        r = setup_resolv_conf(directory);
        if (r < 0)
                return r;

        r = setup_machine_id(directory);
        if (r < 0)
                return r;

        r = setup_journal(directory);
        if (r < 0)
                return r;

        /* The same stuff as the $container env var, but nicely readable for the entire payload */
        p = prefix_roota(directory, "/run/host/container-manager");
        (void) write_string_file(p, arg_container_service_name, WRITE_STRING_FILE_CREATE);

        /* The same stuff as the $container_uuid env var */
        p = prefix_roota(directory, "/run/host/container-uuid");
        (void) write_string_filef(p, WRITE_STRING_FILE_CREATE, SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(arg_uuid));

        if (!arg_use_cgns) {
                r = mount_cgroups(
                                directory,
                                arg_unified_cgroup_hierarchy,
                                arg_userns_mode != USER_NAMESPACE_NO,
                                arg_uid_shift,
                                arg_uid_range,
                                arg_selinux_apifs_context,
                                false);
                if (r < 0)
                        return r;
        }

        /* Mark everything as shared so our mounts get propagated down. This is required to make new bind
         * mounts available in systemd services inside the container that create a new mount namespace.  See
         * https://github.com/systemd/systemd/issues/3860 Further submounts (such as /dev) done after this
         * will inherit the shared propagation mode.
         *
         * IMPORTANT: Do not overmount the root directory anymore from now on to enable moving the root
         * directory mount to root later on.
         * https://github.com/systemd/systemd/issues/3847#issuecomment-562735251
         */
        r = mount_switch_root(directory, MS_SHARED);
        if (r < 0)
                return log_error_errno(r, "Failed to move root directory: %m");

        /* We finished setting up the rootfs which is a shared mount. The mount tunnel needs to be a
         * dependent mount otherwise we can't MS_MOVE mounts that were propagated from the host into
         * the container. */
        r = mount_tunnel_open();
        if (r < 0)
                return r;

        if (arg_userns_mode != USER_NAMESPACE_NO) {
                /* In order to mount procfs and sysfs in an unprivileged container the kernel
                 * requires that a fully visible instance is already present in the target mount
                 * namespace. Mount one here so the inner child can mount its own instances. Later
                 * we umount the temporary instances created here before we actually exec the
                 * payload. Since the rootfs is shared the umount will propagate into the container.
                 * Note, the inner child wouldn't be able to unmount the instances on its own since
                 * it doesn't own the originating mount namespace. IOW, the outer child needs to do
                 * this. */
                r = pin_fully_visible_fs();
                if (r < 0)
                        return r;
        }

        fd = setup_notify_child();
        if (fd < 0)
                return fd;

        pid = raw_clone(SIGCHLD|CLONE_NEWNS|
                        arg_clone_ns_flags |
                        (arg_userns_mode != USER_NAMESPACE_NO ? CLONE_NEWUSER : 0));
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork inner child: %m");
        if (pid == 0) {
                fd_outer_socket = safe_close(fd_outer_socket);

                /* The inner child has all namespaces that are requested, so that we all are owned by the
                 * user if user namespaces are turned on. */

                if (arg_network_namespace_path) {
                        r = namespace_enter(-1, -1, netns_fd, -1, -1);
                        if (r < 0)
                                return log_error_errno(r, "Failed to join network namespace: %m");
                }

                r = inner_child(barrier, fd_inner_socket, fds, os_release_pairs);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        l = send(fd_outer_socket, &pid, sizeof(pid), MSG_NOSIGNAL);
        if (l < 0)
                return log_error_errno(errno, "Failed to send PID: %m");
        if (l != sizeof(pid))
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Short write while sending PID.");

        l = send(fd_outer_socket, &arg_uuid, sizeof(arg_uuid), MSG_NOSIGNAL);
        if (l < 0)
                return log_error_errno(errno, "Failed to send machine ID: %m");
        if (l != sizeof(arg_uuid))
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Short write while sending machine ID.");

        l = send_one_fd(fd_outer_socket, fd, 0);
        if (l < 0)
                return log_error_errno(l, "Failed to send notify fd: %m");

        fd_outer_socket = safe_close(fd_outer_socket);
        fd_inner_socket = safe_close(fd_inner_socket);
        netns_fd = safe_close(netns_fd);

        return 0;
}

static int uid_shift_pick(uid_t *shift, LockFile *ret_lock_file) {
        bool tried_hashed = false;
        unsigned n_tries = 100;
        uid_t candidate;
        int r;

        assert(shift);
        assert(ret_lock_file);
        assert(arg_userns_mode == USER_NAMESPACE_PICK);
        assert(arg_uid_range == 0x10000U);

        candidate = *shift;

        (void) mkdir("/run/systemd/nspawn-uid", 0755);

        for (;;) {
                char lock_path[STRLEN("/run/systemd/nspawn-uid/") + DECIMAL_STR_MAX(uid_t) + 1];
                _cleanup_(release_lock_file) LockFile lf = LOCK_FILE_INIT;

                if (--n_tries <= 0)
                        return -EBUSY;

                if (candidate < CONTAINER_UID_BASE_MIN || candidate > CONTAINER_UID_BASE_MAX)
                        goto next;
                if ((candidate & UINT32_C(0xFFFF)) != 0)
                        goto next;

                xsprintf(lock_path, "/run/systemd/nspawn-uid/" UID_FMT, candidate);
                r = make_lock_file(lock_path, LOCK_EX|LOCK_NB, &lf);
                if (r == -EBUSY) /* Range already taken by another nspawn instance */
                        goto next;
                if (r < 0)
                        return r;

                /* Make some superficial checks whether the range is currently known in the user database */
                if (getpwuid(candidate))
                        goto next;
                if (getpwuid(candidate + UINT32_C(0xFFFE)))
                        goto next;
                if (getgrgid(candidate))
                        goto next;
                if (getgrgid(candidate + UINT32_C(0xFFFE)))
                        goto next;

                *ret_lock_file = lf;
                lf = (struct LockFile) LOCK_FILE_INIT;
                *shift = candidate;
                return 0;

        next:
                if (arg_machine && !tried_hashed) {
                        /* Try to hash the base from the container name */

                        static const uint8_t hash_key[] = {
                                0xe1, 0x56, 0xe0, 0xf0, 0x4a, 0xf0, 0x41, 0xaf,
                                0x96, 0x41, 0xcf, 0x41, 0x33, 0x94, 0xff, 0x72
                        };

                        candidate = (uid_t) siphash24(arg_machine, strlen(arg_machine), hash_key);

                        tried_hashed = true;
                } else
                        random_bytes(&candidate, sizeof(candidate));

                candidate = (candidate % (CONTAINER_UID_BASE_MAX - CONTAINER_UID_BASE_MIN)) + CONTAINER_UID_BASE_MIN;
                candidate &= (uid_t) UINT32_C(0xFFFF0000);
        }
}

static int add_one_uid_map(
                char **p,
                uid_t container_uid,
                uid_t host_uid,
                uid_t range) {

        return strextendf(p,
                       UID_FMT " " UID_FMT " " UID_FMT "\n",
                       container_uid, host_uid, range);
}

static int make_uid_map_string(
                const uid_t bind_user_uid[],
                size_t n_bind_user_uid,
                size_t offset,
                char **ret) {

        _cleanup_free_ char *s = NULL;
        uid_t previous_uid = 0;
        int r;

        assert(n_bind_user_uid == 0 || bind_user_uid);
        assert(IN_SET(offset, 0, 2)); /* used to switch between UID and GID map */
        assert(ret);

        /* The bind_user_uid[] array is a series of 4 uid_t values, for each --bind-user= entry one
         * quadruplet, consisting of host and container UID + GID. */

        for (size_t i = 0; i < n_bind_user_uid; i++) {
                uid_t payload_uid = bind_user_uid[i*4+offset],
                        host_uid = bind_user_uid[i*4+offset+1];

                assert(previous_uid <= payload_uid);
                assert(payload_uid < arg_uid_range);

                /* Add a range to close the gap to previous entry */
                if (payload_uid > previous_uid) {
                        r = add_one_uid_map(&s, previous_uid, arg_uid_shift + previous_uid, payload_uid - previous_uid);
                        if (r < 0)
                                return r;
                }

                /* Map this specific user */
                r = add_one_uid_map(&s, payload_uid, host_uid, 1);
                if (r < 0)
                        return r;

                previous_uid = payload_uid + 1;
        }

        /* And add a range to close the gap to finish the range */
        if (arg_uid_range > previous_uid) {
                r = add_one_uid_map(&s, previous_uid, arg_uid_shift + previous_uid, arg_uid_range - previous_uid);
                if (r < 0)
                        return r;
        }

        assert(s);

        *ret = TAKE_PTR(s);
        return 0;
}

static int setup_uid_map(
                pid_t pid,
                const uid_t bind_user_uid[],
                size_t n_bind_user_uid) {

        char uid_map[STRLEN("/proc//uid_map") + DECIMAL_STR_MAX(uid_t) + 1];
        _cleanup_free_ char *s = NULL;
        int r;

        assert(pid > 1);

        /* Build the UID map string */
        if (make_uid_map_string(bind_user_uid, n_bind_user_uid, 0, &s) < 0) /* offset=0 contains the UID pair */
                return log_oom();

        xsprintf(uid_map, "/proc/" PID_FMT "/uid_map", pid);
        r = write_string_file(uid_map, s, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_error_errno(r, "Failed to write UID map: %m");

        /* And now build the GID map string */
        s = mfree(s);
        if (make_uid_map_string(bind_user_uid, n_bind_user_uid, 2, &s) < 0) /* offset=2 contains the GID pair */
                return log_oom();

        xsprintf(uid_map, "/proc/" PID_FMT "/gid_map", pid);
        r = write_string_file(uid_map, s, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_error_errno(r, "Failed to write GID map: %m");

        return 0;
}

static int nspawn_dispatch_notify_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        char buf[NOTIFY_BUFFER_MAX+1];
        char *p = NULL;
        struct iovec iovec = {
                .iov_base = buf,
                .iov_len = sizeof(buf)-1,
        };
        CMSG_BUFFER_TYPE(CMSG_SPACE(sizeof(struct ucred)) +
                         CMSG_SPACE(sizeof(int) * NOTIFY_FD_MAX)) control;
        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct ucred *ucred;
        ssize_t n;
        pid_t inner_child_pid;
        _cleanup_strv_free_ char **tags = NULL;
        int r;

        assert(userdata);

        inner_child_pid = PTR_TO_PID(userdata);

        if (revents != EPOLLIN) {
                log_warning("Got unexpected poll event for notify fd.");
                return 0;
        }

        n = recvmsg_safe(fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        if (ERRNO_IS_NEG_TRANSIENT(n))
                return 0;
        else if (n == -EXFULL) {
                log_warning("Got message with truncated control data (too many fds sent?), ignoring.");
                return 0;
        } else if (n < 0)
                return log_warning_errno(n, "Couldn't read notification socket: %m");

        cmsg_close_all(&msghdr);

        ucred = CMSG_FIND_DATA(&msghdr, SOL_SOCKET, SCM_CREDENTIALS, struct ucred);
        if (!ucred || ucred->pid != inner_child_pid) {
                log_debug("Received notify message without valid credentials. Ignoring.");
                return 0;
        }

        if ((size_t) n >= sizeof(buf)) {
                log_warning("Received notify message exceeded maximum size. Ignoring.");
                return 0;
        }

        buf[n] = 0;
        tags = strv_split(buf, "\n\r");
        if (!tags)
                return log_oom();

        if (strv_contains(tags, "READY=1")) {
                r = sd_notify(false, "READY=1\n");
                if (r < 0)
                        log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");
        }

        p = strv_find_startswith(tags, "STATUS=");
        if (p)
                (void) sd_notifyf(false, "STATUS=Container running: %s", p);

        return 0;
}

static int setup_notify_parent(sd_event *event, int fd, pid_t *inner_child_pid, sd_event_source **notify_event_source) {
        int r;

        r = sd_event_add_io(event, notify_event_source, fd, EPOLLIN, nspawn_dispatch_notify_fd, inner_child_pid);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate notify event source: %m");

        (void) sd_event_source_set_description(*notify_event_source, "nspawn-notify");

        return 0;
}

static int merge_settings(Settings *settings, const char *path) {
        int rl;

        assert(settings);
        assert(path);

        /* Copy over bits from the settings, unless they have been explicitly masked by command line switches. Note
         * that this steals the fields of the Settings* structure, and hence modifies it. */

        if ((arg_settings_mask & SETTING_START_MODE) == 0 &&
            settings->start_mode >= 0) {
                arg_start_mode = settings->start_mode;
                strv_free_and_replace(arg_parameters, settings->parameters);
        }

        if ((arg_settings_mask & SETTING_EPHEMERAL) == 0 &&
            settings->ephemeral >= 0)
                arg_ephemeral = settings->ephemeral;

        if ((arg_settings_mask & SETTING_DIRECTORY) == 0 &&
            settings->root) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring root directory setting, file %s is not trusted.", path);
                else
                        free_and_replace(arg_directory, settings->root);
        }

        if ((arg_settings_mask & SETTING_PIVOT_ROOT) == 0 &&
            settings->pivot_root_new) {
                free_and_replace(arg_pivot_root_new, settings->pivot_root_new);
                free_and_replace(arg_pivot_root_old, settings->pivot_root_old);
        }

        if ((arg_settings_mask & SETTING_WORKING_DIRECTORY) == 0 &&
            settings->working_directory)
                free_and_replace(arg_chdir, settings->working_directory);

        if ((arg_settings_mask & SETTING_ENVIRONMENT) == 0 &&
            settings->environment)
                strv_free_and_replace(arg_setenv, settings->environment);

        if ((arg_settings_mask & SETTING_USER) == 0) {

                if (settings->user)
                        free_and_replace(arg_user, settings->user);

                if (uid_is_valid(settings->uid))
                        arg_uid = settings->uid;
                if (gid_is_valid(settings->gid))
                        arg_gid = settings->gid;
                if (settings->n_supplementary_gids > 0) {
                        free_and_replace(arg_supplementary_gids, settings->supplementary_gids);
                        arg_n_supplementary_gids = settings->n_supplementary_gids;
                }
        }

        if ((arg_settings_mask & SETTING_CAPABILITY) == 0) {
                uint64_t plus, minus;
                uint64_t network_minus = 0;
                uint64_t ambient;

                /* Note that we copy both the simple plus/minus caps here, and the full quintet from the
                 * Settings structure */

                plus = settings->capability;
                minus = settings->drop_capability;

                if ((arg_settings_mask & SETTING_NETWORK) == 0 &&
                    settings_network_configured(settings)) {
                        if (settings_private_network(settings))
                                plus |= UINT64_C(1) << CAP_NET_ADMIN;
                        else
                                network_minus |= UINT64_C(1) << CAP_NET_ADMIN;
                }

                if (!arg_settings_trusted && plus != 0) {
                        if (settings->capability != 0)
                                log_warning("Ignoring Capability= setting, file %s is not trusted.", path);
                } else {
                        arg_caps_retain &= ~network_minus;
                        arg_caps_retain |= plus;
                }

                arg_caps_retain &= ~minus;

                /* Copy the full capabilities over too */
                if (capability_quintet_is_set(&settings->full_capabilities)) {
                        if (!arg_settings_trusted)
                                log_warning("Ignoring capability settings, file %s is not trusted.", path);
                        else
                                arg_full_capabilities = settings->full_capabilities;
                }

                ambient = settings->ambient_capability;
                if (!arg_settings_trusted && ambient != 0)
                        log_warning("Ignoring AmbientCapability= setting, file %s is not trusted.", path);
                else
                        arg_caps_ambient |= ambient;
        }

        if ((arg_settings_mask & SETTING_KILL_SIGNAL) == 0 &&
            settings->kill_signal > 0)
                arg_kill_signal = settings->kill_signal;

        if ((arg_settings_mask & SETTING_PERSONALITY) == 0 &&
            settings->personality != PERSONALITY_INVALID)
                arg_personality = settings->personality;

        if ((arg_settings_mask & SETTING_MACHINE_ID) == 0 &&
            !sd_id128_is_null(settings->machine_id)) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring MachineID= setting, file %s is not trusted.", path);
                else
                        arg_uuid = settings->machine_id;
        }

        if ((arg_settings_mask & SETTING_READ_ONLY) == 0 &&
            settings->read_only >= 0)
                arg_read_only = settings->read_only;

        if ((arg_settings_mask & SETTING_VOLATILE_MODE) == 0 &&
            settings->volatile_mode != _VOLATILE_MODE_INVALID)
                arg_volatile_mode = settings->volatile_mode;

        if ((arg_settings_mask & SETTING_CUSTOM_MOUNTS) == 0 &&
            settings->n_custom_mounts > 0) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring TemporaryFileSystem=, Bind= and BindReadOnly= settings, file %s is not trusted.", path);
                else {
                        custom_mount_free_all(arg_custom_mounts, arg_n_custom_mounts);
                        arg_custom_mounts = TAKE_PTR(settings->custom_mounts);
                        arg_n_custom_mounts = settings->n_custom_mounts;
                        settings->n_custom_mounts = 0;
                }
        }

        if ((arg_settings_mask & SETTING_NETWORK) == 0 &&
            settings_network_configured(settings)) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring network settings, file %s is not trusted.", path);
                else {
                        arg_network_veth = settings_network_veth(settings);
                        arg_private_network = settings_private_network(settings);

                        strv_free_and_replace(arg_network_interfaces, settings->network_interfaces);
                        strv_free_and_replace(arg_network_macvlan, settings->network_macvlan);
                        strv_free_and_replace(arg_network_ipvlan, settings->network_ipvlan);
                        strv_free_and_replace(arg_network_veth_extra, settings->network_veth_extra);

                        free_and_replace(arg_network_bridge, settings->network_bridge);
                        free_and_replace(arg_network_zone, settings->network_zone);

                        free_and_replace(arg_network_namespace_path, settings->network_namespace_path);
                }
        }

        if ((arg_settings_mask & SETTING_EXPOSE_PORTS) == 0 &&
            settings->expose_ports) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring Port= setting, file %s is not trusted.", path);
                else {
                        expose_port_free_all(arg_expose_ports);
                        arg_expose_ports = TAKE_PTR(settings->expose_ports);
                }
        }

        if ((arg_settings_mask & SETTING_USERNS) == 0 &&
            settings->userns_mode != _USER_NAMESPACE_MODE_INVALID) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring PrivateUsers= and PrivateUsersChown= settings, file %s is not trusted.", path);
                else {
                        arg_userns_mode = settings->userns_mode;
                        arg_uid_shift = settings->uid_shift;
                        arg_uid_range = settings->uid_range;
                        arg_userns_ownership = settings->userns_ownership;
                }
        }

        if ((arg_settings_mask & SETTING_BIND_USER) == 0 &&
            !strv_isempty(settings->bind_user))
                strv_free_and_replace(arg_bind_user, settings->bind_user);

        if ((arg_settings_mask & SETTING_NOTIFY_READY) == 0 &&
            settings->notify_ready >= 0)
                arg_notify_ready = settings->notify_ready;

        if ((arg_settings_mask & SETTING_SYSCALL_FILTER) == 0) {

                if (!strv_isempty(settings->syscall_allow_list) || !strv_isempty(settings->syscall_deny_list)) {
                        if (!arg_settings_trusted && !strv_isempty(settings->syscall_allow_list))
                                log_warning("Ignoring SystemCallFilter= settings, file %s is not trusted.", path);
                        else {
                                strv_free_and_replace(arg_syscall_allow_list, settings->syscall_allow_list);
                                strv_free_and_replace(arg_syscall_deny_list, settings->syscall_deny_list);
                        }
                }

#if HAVE_SECCOMP
                if (settings->seccomp) {
                        if (!arg_settings_trusted)
                                log_warning("Ignoring SECCOMP filter, file %s is not trusted.", path);
                        else {
                                seccomp_release(arg_seccomp);
                                arg_seccomp = TAKE_PTR(settings->seccomp);
                        }
                }
#endif
        }

        for (rl = 0; rl < _RLIMIT_MAX; rl ++) {
                if ((arg_settings_mask & (SETTING_RLIMIT_FIRST << rl)))
                        continue;

                if (!settings->rlimit[rl])
                        continue;

                if (!arg_settings_trusted) {
                        log_warning("Ignoring Limit%s= setting, file '%s' is not trusted.", rlimit_to_string(rl), path);
                        continue;
                }

                free_and_replace(arg_rlimit[rl], settings->rlimit[rl]);
        }

        if ((arg_settings_mask & SETTING_HOSTNAME) == 0 &&
            settings->hostname)
                free_and_replace(arg_hostname, settings->hostname);

        if ((arg_settings_mask & SETTING_NO_NEW_PRIVILEGES) == 0 &&
            settings->no_new_privileges >= 0)
                arg_no_new_privileges = settings->no_new_privileges;

        if ((arg_settings_mask & SETTING_OOM_SCORE_ADJUST) == 0 &&
            settings->oom_score_adjust_set) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring OOMScoreAdjust= setting, file '%s' is not trusted.", path);
                else {
                        arg_oom_score_adjust = settings->oom_score_adjust;
                        arg_oom_score_adjust_set = true;
                }
        }

        if ((arg_settings_mask & SETTING_CPU_AFFINITY) == 0 &&
            settings->cpu_set.set) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring CPUAffinity= setting, file '%s' is not trusted.", path);
                else {
                        cpu_set_reset(&arg_cpu_set);
                        arg_cpu_set = TAKE_STRUCT(settings->cpu_set);
                }
        }

        if ((arg_settings_mask & SETTING_RESOLV_CONF) == 0 &&
            settings->resolv_conf != _RESOLV_CONF_MODE_INVALID)
                arg_resolv_conf = settings->resolv_conf;

        if ((arg_settings_mask & SETTING_LINK_JOURNAL) == 0 &&
            settings->link_journal != _LINK_JOURNAL_INVALID) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring journal link setting, file '%s' is not trusted.", path);
                else {
                        arg_link_journal = settings->link_journal;
                        arg_link_journal_try = settings->link_journal_try;
                }
        }

        if ((arg_settings_mask & SETTING_TIMEZONE) == 0 &&
            settings->timezone != _TIMEZONE_MODE_INVALID)
                arg_timezone = settings->timezone;

        if ((arg_settings_mask & SETTING_SLICE) == 0 &&
            settings->slice) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring slice setting, file '%s' is not trusted.", path);
                else
                        free_and_replace(arg_slice, settings->slice);
        }

        if ((arg_settings_mask & SETTING_USE_CGNS) == 0 &&
            settings->use_cgns >= 0) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring cgroup namespace setting, file '%s' is not trusted.", path);
                else
                        arg_use_cgns = settings->use_cgns;
        }

        if ((arg_settings_mask & SETTING_CLONE_NS_FLAGS) == 0 &&
            settings->clone_ns_flags != ULONG_MAX) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring namespace setting, file '%s' is not trusted.", path);
                else
                        arg_clone_ns_flags = settings->clone_ns_flags;
        }

        if ((arg_settings_mask & SETTING_CONSOLE_MODE) == 0 &&
            settings->console_mode >= 0) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring console mode setting, file '%s' is not trusted.", path);
                else
                        arg_console_mode = settings->console_mode;
        }

        if ((arg_settings_mask & SETTING_SUPPRESS_SYNC) == 0 &&
            settings->suppress_sync >= 0)
                arg_suppress_sync = settings->suppress_sync;

        /* The following properties can only be set through the OCI settings logic, not from the command line, hence we
         * don't consult arg_settings_mask for them. */

        sd_bus_message_unref(arg_property_message);
        arg_property_message = TAKE_PTR(settings->properties);

        arg_console_width = settings->console_width;
        arg_console_height = settings->console_height;

        device_node_array_free(arg_extra_nodes, arg_n_extra_nodes);
        arg_extra_nodes = TAKE_PTR(settings->extra_nodes);
        arg_n_extra_nodes = settings->n_extra_nodes;
        settings->n_extra_nodes = 0;

        return 0;
}

static int load_settings(void) {
        _cleanup_(settings_freep) Settings *settings = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        if (arg_oci_bundle)
                return 0;

        /* If all settings are masked, there's no point in looking for
         * the settings file */
        if (FLAGS_SET(arg_settings_mask, _SETTINGS_MASK_ALL))
                return 0;

        /* We first look in the admin's directories in /etc and /run */
        FOREACH_STRING(i, "/etc/systemd/nspawn", "/run/systemd/nspawn") {
                _cleanup_free_ char *j = NULL;

                j = path_join(i, arg_settings_filename);
                if (!j)
                        return log_oom();

                f = fopen(j, "re");
                if (f) {
                        p = TAKE_PTR(j);

                        /* By default, we trust configuration from /etc and /run */
                        if (arg_settings_trusted < 0)
                                arg_settings_trusted = true;

                        break;
                }

                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open %s: %m", j);
        }

        if (!f) {
                /* After that, let's look for a file next to the
                 * actual image we shall boot. */

                if (arg_image) {
                        r = file_in_same_dir(arg_image, arg_settings_filename, &p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to generate settings path from image path: %m");
                } else if (arg_directory) {
                        r = file_in_same_dir(arg_directory, arg_settings_filename, &p);
                        if (r < 0 && r != -EADDRNOTAVAIL) /* if directory is root fs, don't complain */
                                return log_error_errno(r, "Failed to generate settings path from directory path: %m");
                }

                if (p) {
                        f = fopen(p, "re");
                        if (!f && errno != ENOENT)
                                return log_error_errno(errno, "Failed to open %s: %m", p);

                        /* By default, we do not trust configuration from /var/lib/machines */
                        if (arg_settings_trusted < 0)
                                arg_settings_trusted = false;
                }
        }

        if (!f)
                return 0;

        log_debug("Settings are trusted: %s", yes_no(arg_settings_trusted));

        r = settings_load(f, p, &settings);
        if (r < 0)
                return r;

        return merge_settings(settings, p);
}

static int load_oci_bundle(void) {
        _cleanup_(settings_freep) Settings *settings = NULL;
        int r;

        if (!arg_oci_bundle)
                return 0;

        /* By default let's trust OCI bundles */
        if (arg_settings_trusted < 0)
                arg_settings_trusted = true;

        r = oci_load(NULL, arg_oci_bundle, &settings);
        if (r < 0)
                return r;

        return merge_settings(settings, arg_oci_bundle);
}

static int run_container(
               DissectedImage *dissected_image,
               FDSet *fds,
               char veth_name[IFNAMSIZ], bool *veth_created,
               struct ExposeArgs *expose_args,
               int *master, pid_t *pid, int *ret) {

        static const struct sigaction sa = {
                .sa_handler = nop_signal_handler,
                .sa_flags = SA_NOCLDSTOP|SA_RESTART,
        };

        _cleanup_(release_lock_file) LockFile uid_shift_lock = LOCK_FILE_INIT;
        _cleanup_close_ int etc_passwd_lock = -EBADF;
        _cleanup_close_pair_ int
                fd_inner_socket_pair[2] = EBADF_PAIR,
                fd_outer_socket_pair[2] = EBADF_PAIR;

        _cleanup_close_ int notify_socket = -EBADF, mntns_fd = -EBADF, fd_kmsg_fifo = -EBADF;
        _cleanup_(barrier_destroy) Barrier barrier = BARRIER_NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *notify_event_source = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(pty_forward_freep) PTYForward *forward = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ uid_t *bind_user_uid = NULL;
        size_t n_bind_user_uid = 0;
        ContainerStatus container_status = 0;
        int ifi = 0, r;
        ssize_t l;
        sigset_t mask_chld;
        _cleanup_close_ int child_netns_fd = -EBADF;

        assert_se(sigemptyset(&mask_chld) == 0);
        assert_se(sigaddset(&mask_chld, SIGCHLD) == 0);

        if (arg_userns_mode == USER_NAMESPACE_PICK) {
                /* When we shall pick the UID/GID range, let's first lock /etc/passwd, so that we can safely
                 * check with getpwuid() if the specific user already exists. Note that /etc might be
                 * read-only, in which case this will fail with EROFS. But that's really OK, as in that case we
                 * can be reasonably sure that no users are going to be added. Note that getpwuid() checks are
                 * really just an extra safety net. We kinda assume that the UID range we allocate from is
                 * really ours. */

                etc_passwd_lock = take_etc_passwd_lock(NULL);
                if (etc_passwd_lock < 0 && etc_passwd_lock != -EROFS)
                        return log_error_errno(etc_passwd_lock, "Failed to take /etc/passwd lock: %m");
        }

        r = barrier_create(&barrier);
        if (r < 0)
                return log_error_errno(r, "Cannot initialize IPC barrier: %m");

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, fd_inner_socket_pair) < 0)
                return log_error_errno(errno, "Failed to create inner socket pair: %m");

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, fd_outer_socket_pair) < 0)
                return log_error_errno(errno, "Failed to create outer socket pair: %m");

        /* Child can be killed before execv(), so handle SIGCHLD in order to interrupt
         * parent's blocking calls and give it a chance to call wait() and terminate. */
        r = sigprocmask(SIG_UNBLOCK, &mask_chld, NULL);
        if (r < 0)
                return log_error_errno(errno, "Failed to change the signal mask: %m");

        r = sigaction(SIGCHLD, &sa, NULL);
        if (r < 0)
                return log_error_errno(errno, "Failed to install SIGCHLD handler: %m");

        if (arg_network_namespace_path) {
                child_netns_fd = open(arg_network_namespace_path, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (child_netns_fd < 0)
                        return log_error_errno(errno, "Cannot open file %s: %m", arg_network_namespace_path);

                r = fd_is_ns(child_netns_fd, CLONE_NEWNET);
                if (r == -EUCLEAN)
                        log_debug_errno(r, "Cannot determine if passed network namespace path '%s' really refers to a network namespace, assuming it does.", arg_network_namespace_path);
                else if (r < 0)
                        return log_error_errno(r, "Failed to check %s fs type: %m", arg_network_namespace_path);
                else if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Path %s doesn't refer to a network namespace, refusing.", arg_network_namespace_path);
        }

        *pid = raw_clone(SIGCHLD|CLONE_NEWNS);
        if (*pid < 0)
                return log_error_errno(errno, "clone() failed%s: %m",
                                       errno == EINVAL ?
                                       ", do you have namespace support enabled in your kernel? (You need UTS, IPC, PID and NET namespacing built in)" : "");

        if (*pid == 0) {
                /* The outer child only has a file system namespace. */
                barrier_set_role(&barrier, BARRIER_CHILD);

                fd_inner_socket_pair[0] = safe_close(fd_inner_socket_pair[0]);
                fd_outer_socket_pair[0] = safe_close(fd_outer_socket_pair[0]);

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();

                r = outer_child(&barrier,
                                arg_directory,
                                dissected_image,
                                fd_outer_socket_pair[1],
                                fd_inner_socket_pair[1],
                                fds,
                                child_netns_fd);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        barrier_set_role(&barrier, BARRIER_PARENT);

        fdset_close(fds);

        fd_inner_socket_pair[1] = safe_close(fd_inner_socket_pair[1]);
        fd_outer_socket_pair[1] = safe_close(fd_outer_socket_pair[1]);

        if (arg_userns_mode != USER_NAMESPACE_NO) {
                mntns_fd = receive_one_fd(fd_outer_socket_pair[0], 0);
                if (mntns_fd < 0)
                        return log_error_errno(mntns_fd, "Failed to receive mount namespace fd from outer child: %m");

                /* The child just let us know the UID shift it might have read from the image. */
                l = recv(fd_outer_socket_pair[0], &arg_uid_shift, sizeof arg_uid_shift, 0);
                if (l < 0)
                        return log_error_errno(errno, "Failed to read UID shift: %m");
                if (l != sizeof arg_uid_shift)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read while reading UID shift.");

                if (arg_userns_mode == USER_NAMESPACE_PICK) {
                        /* If we are supposed to pick the UID shift, let's try to use the shift read from the
                         * image, but if that's already in use, pick a new one, and report back to the child,
                         * which one we now picked. */

                        r = uid_shift_pick(&arg_uid_shift, &uid_shift_lock);
                        if (r < 0)
                                return log_error_errno(r, "Failed to pick suitable UID/GID range: %m");

                        l = send(fd_outer_socket_pair[0], &arg_uid_shift, sizeof arg_uid_shift, MSG_NOSIGNAL);
                        if (l < 0)
                                return log_error_errno(errno, "Failed to send UID shift: %m");
                        if (l != sizeof arg_uid_shift)
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write while writing UID shift.");
                }

                n_bind_user_uid = strv_length(arg_bind_user);
                if (n_bind_user_uid > 0) {
                        /* Right after the UID shift, we'll receive the list of UID mappings for the
                         * --bind-user= logic. Always a quadruplet of payload and host UID + GID. */

                        bind_user_uid = new(uid_t, n_bind_user_uid*4);
                        if (!bind_user_uid)
                                return log_oom();

                        for (size_t i = 0; i < n_bind_user_uid; i++) {
                                l = recv(fd_outer_socket_pair[0], bind_user_uid + i*4, sizeof(uid_t)*4, 0);
                                if (l < 0)
                                        return log_error_errno(errno, "Failed to read user UID map pair: %m");
                                if (l != sizeof(uid_t)*4)
                                        return log_full_errno(l == 0 ? LOG_DEBUG : LOG_WARNING,
                                                              SYNTHETIC_ERRNO(EIO),
                                                              "Short read while reading bind user UID pairs.");
                        }
                }
        }

        if (arg_unified_cgroup_hierarchy == CGROUP_UNIFIED_UNKNOWN) {
                /* The child let us know the support cgroup mode it might have read from the image. */
                l = recv(fd_outer_socket_pair[0], &arg_unified_cgroup_hierarchy, sizeof(arg_unified_cgroup_hierarchy), 0);
                if (l < 0)
                        return log_error_errno(errno, "Failed to read cgroup mode: %m");
                if (l != sizeof(arg_unified_cgroup_hierarchy))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read while reading cgroup mode (%zi bytes).%s",
                                               l, l == 0 ? " The child is most likely dead." : "");
        }

        /* Wait for the outer child. */
        r = wait_for_terminate_and_check("(sd-namespace)", *pid, WAIT_LOG_ABNORMAL);
        if (r < 0)
                return r;
        if (r != EXIT_SUCCESS)
                return -EIO;

        /* And now retrieve the PID of the inner child. */
        l = recv(fd_outer_socket_pair[0], pid, sizeof *pid, 0);
        if (l < 0)
                return log_error_errno(errno, "Failed to read inner child PID: %m");
        if (l != sizeof *pid)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read while reading inner child PID.");

        /* We also retrieve container UUID in case it was generated by outer child */
        l = recv(fd_outer_socket_pair[0], &arg_uuid, sizeof arg_uuid, 0);
        if (l < 0)
                return log_error_errno(errno, "Failed to read container machine ID: %m");
        if (l != sizeof(arg_uuid))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read while reading container machined ID.");

        /* We also retrieve the socket used for notifications generated by outer child */
        notify_socket = receive_one_fd(fd_outer_socket_pair[0], 0);
        if (notify_socket < 0)
                return log_error_errno(notify_socket,
                                       "Failed to receive notification socket from the outer child: %m");

        log_debug("Init process invoked as PID "PID_FMT, *pid);

        if (arg_userns_mode != USER_NAMESPACE_NO) {
                if (!barrier_place_and_sync(&barrier)) /* #1 */
                        return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "Child died too early.");

                r = setup_uid_map(*pid, bind_user_uid, n_bind_user_uid);
                if (r < 0)
                        return r;

                (void) barrier_place(&barrier); /* #2 */
        }

        if (arg_private_network) {
                if (!arg_network_namespace_path) {
                        /* Wait until the child has unshared its network namespace. */
                        if (!barrier_place_and_sync(&barrier)) /* #3 */
                                return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "Child died too early");
                }

                if (child_netns_fd < 0) {
                        /* Make sure we have an open file descriptor to the child's network
                         * namespace so it stays alive even if the child exits. */
                        r = namespace_open(*pid, NULL, NULL, &child_netns_fd, NULL, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to open child network namespace: %m");
                }

                r = move_network_interfaces(child_netns_fd, arg_network_interfaces);
                if (r < 0)
                        return r;

                if (arg_network_veth) {
                        r = setup_veth(arg_machine, *pid, veth_name,
                                       arg_network_bridge || arg_network_zone, &arg_network_provided_mac);
                        if (r < 0)
                                return r;
                        else if (r > 0)
                                ifi = r;

                        if (arg_network_bridge) {
                                /* Add the interface to a bridge */
                                r = setup_bridge(veth_name, arg_network_bridge, false);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        ifi = r;
                        } else if (arg_network_zone) {
                                /* Add the interface to a bridge, possibly creating it */
                                r = setup_bridge(veth_name, arg_network_zone, true);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        ifi = r;
                        }
                }

                r = setup_veth_extra(arg_machine, *pid, arg_network_veth_extra);
                if (r < 0)
                        return r;

                /* We created the primary and extra veth links now; let's remember this, so that we know to
                   remove them later on. Note that we don't bother with removing veth links that were created
                   here when their setup failed half-way, because in that case the kernel should be able to
                   remove them on its own, since they cannot be referenced by anything yet. */
                *veth_created = true;

                r = setup_macvlan(arg_machine, *pid, arg_network_macvlan);
                if (r < 0)
                        return r;

                r = setup_ipvlan(arg_machine, *pid, arg_network_ipvlan);
                if (r < 0)
                        return r;
        }

        if (arg_register || !arg_keep_unit) {
                r = sd_bus_default_system(&bus);
                if (r < 0)
                        return log_error_errno(r, "Failed to open system bus: %m");

                r = sd_bus_set_close_on_exit(bus, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to disable close-on-exit behaviour: %m");
        }

        if (!arg_keep_unit) {
                /* When a new scope is created for this container, then we'll be registered as its controller, in which
                 * case PID 1 will send us a friendly RequestStop signal, when it is asked to terminate the
                 * scope. Let's hook into that, and cleanly shut down the container, and print a friendly message. */

                r = sd_bus_match_signal_async(
                                bus,
                                NULL,
                                "org.freedesktop.systemd1",
                                NULL,
                                "org.freedesktop.systemd1.Scope",
                                "RequestStop",
                                on_request_stop, NULL, PID_TO_PTR(*pid));
                if (r < 0)
                        return log_error_errno(r, "Failed to request RequestStop match: %m");
        }

        if (arg_register) {
                r = register_machine(
                                bus,
                                arg_machine,
                                *pid,
                                arg_directory,
                                arg_uuid,
                                ifi,
                                arg_slice,
                                arg_custom_mounts, arg_n_custom_mounts,
                                arg_kill_signal,
                                arg_property,
                                arg_property_message,
                                arg_keep_unit,
                                arg_container_service_name,
                                arg_start_mode);
                if (r < 0)
                        return r;

        } else if (!arg_keep_unit) {
                r = allocate_scope(
                                bus,
                                arg_machine,
                                *pid,
                                arg_slice,
                                arg_custom_mounts, arg_n_custom_mounts,
                                arg_kill_signal,
                                arg_property,
                                arg_property_message,
                                /* allow_pidfds= */ true,
                                arg_start_mode);
                if (r < 0)
                        return r;

        } else if (arg_slice || arg_property)
                log_notice("Machine and scope registration turned off, --slice= and --property= settings will have no effect.");

        r = create_subcgroup(*pid, arg_keep_unit, arg_unified_cgroup_hierarchy);
        if (r < 0)
                return r;

        r = sync_cgroup(*pid, arg_unified_cgroup_hierarchy, arg_uid_shift);
        if (r < 0)
                return r;

        r = chown_cgroup(*pid, arg_unified_cgroup_hierarchy, arg_uid_shift);
        if (r < 0)
                return r;

        /* Notify the child that the parent is ready with all
         * its setup (including cgroup-ification), and that
         * the child can now hand over control to the code to
         * run inside the container. */
        (void) barrier_place(&barrier); /* #4 */

        /* Block SIGCHLD here, before notifying child.
         * process_pty() will handle it with the other signals. */
        assert_se(sigprocmask(SIG_BLOCK, &mask_chld, NULL) >= 0);

        /* Reset signal to default */
        r = default_signals(SIGCHLD);
        if (r < 0)
                return log_error_errno(r, "Failed to reset SIGCHLD: %m");

        r = sd_event_new(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get default event source: %m");

        (void) sd_event_set_watchdog(event, true);

        if (bus) {
                r = sd_bus_attach_event(bus, event, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach bus to event loop: %m");
        }

        r = setup_notify_parent(event, notify_socket, PID_TO_PTR(*pid), &notify_event_source);
        if (r < 0)
                return r;

        /* Wait that the child is completely ready now, and has mounted their own copies of procfs and so on,
         * before we take the fully visible instances away. */
        if (!barrier_sync(&barrier)) /* #5.1 */
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "Child died too early.");

        if (arg_userns_mode != USER_NAMESPACE_NO) {
                r = wipe_fully_visible_fs(mntns_fd);
                if (r < 0)
                        return r;
                mntns_fd = safe_close(mntns_fd);
        }

        /* And now let the child know that we completed removing the procfs instances, and it can start the
         * payload. */
        if (!barrier_place(&barrier)) /* #5.2 */
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "Child died too early.");

        /* At this point we have made use of the UID we picked, and thus nss-systemd/systemd-machined.service
         * will make them appear in getpwuid(), thus we can release the /etc/passwd lock. */
        etc_passwd_lock = safe_close(etc_passwd_lock);

        (void) sd_notifyf(false,
                          "STATUS=Container running.\n"
                          "X_NSPAWN_LEADER_PID=" PID_FMT, *pid);
        if (!arg_notify_ready) {
                r = sd_notify(false, "READY=1\n");
                if (r < 0)
                        log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");
        }

        if (arg_kill_signal > 0) {
                /* Try to kill the init system on SIGINT or SIGTERM */
                (void) sd_event_add_signal(event, NULL, SIGINT, on_orderly_shutdown, PID_TO_PTR(*pid));
                (void) sd_event_add_signal(event, NULL, SIGTERM, on_orderly_shutdown, PID_TO_PTR(*pid));
        } else {
                /* Immediately exit */
                (void) sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
                (void) sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
        }

        (void) sd_event_add_signal(event, NULL, SIGRTMIN+18, sigrtmin18_handler, NULL);

        r = sd_event_add_memory_pressure(event, NULL, NULL, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed allocate memory pressure event source, ignoring: %m");

        /* Exit when the child exits */
        (void) sd_event_add_signal(event, NULL, SIGCHLD, on_sigchld, PID_TO_PTR(*pid));

        /* Retrieve the kmsg fifo allocated by inner child */
        fd_kmsg_fifo = receive_one_fd(fd_inner_socket_pair[0], 0);
        if (fd_kmsg_fifo < 0)
                return log_error_errno(fd_kmsg_fifo, "Failed to receive kmsg fifo from inner child: %m");

        if (arg_expose_ports) {
                r = expose_port_watch_rtnl(event, fd_inner_socket_pair[0], on_address_change, expose_args, &rtnl);
                if (r < 0)
                        return r;

                (void) expose_port_execute(rtnl, &expose_args->fw_ctx, arg_expose_ports, AF_INET, &expose_args->address4);
                (void) expose_port_execute(rtnl, &expose_args->fw_ctx, arg_expose_ports, AF_INET6, &expose_args->address6);
        }

        if (arg_console_mode != CONSOLE_PIPE) {
                _cleanup_close_ int fd = -EBADF;
                PTYForwardFlags flags = 0;

                /* Retrieve the master pty allocated by inner child */
                fd = receive_one_fd(fd_inner_socket_pair[0], 0);
                if (fd < 0)
                        return log_error_errno(fd, "Failed to receive master pty from the inner child: %m");

                switch (arg_console_mode) {

                case CONSOLE_READ_ONLY:
                        flags |= PTY_FORWARD_READ_ONLY;

                        _fallthrough_;

                case CONSOLE_INTERACTIVE:
                        flags |= PTY_FORWARD_IGNORE_VHANGUP;

                        r = pty_forward_new(event, fd, flags, &forward);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create PTY forwarder: %m");

                        if (arg_console_width != UINT_MAX || arg_console_height != UINT_MAX)
                                (void) pty_forward_set_width_height(forward,
                                                                    arg_console_width,
                                                                    arg_console_height);
                        break;

                default:
                        assert(arg_console_mode == CONSOLE_PASSIVE);
                }

                *master = TAKE_FD(fd);
        }

        fd_inner_socket_pair[0] = safe_close(fd_inner_socket_pair[0]);

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        if (forward) {
                char last_char = 0;

                (void) pty_forward_get_last_char(forward, &last_char);
                forward = pty_forward_free(forward);

                if (!arg_quiet && last_char != '\n')
                        putc('\n', stdout);
        }

        /* Kill if it is not dead yet anyway */
        if (!arg_register && !arg_keep_unit && bus)
                terminate_scope(bus, arg_machine);

        /* Normally redundant, but better safe than sorry */
        (void) kill(*pid, SIGKILL);

        fd_kmsg_fifo = safe_close(fd_kmsg_fifo);

        if (arg_private_network) {
                /* Move network interfaces back to the parent network namespace. We use `safe_fork`
                 * to avoid having to move the parent to the child network namespace. */
                r = safe_fork(NULL, FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_WAIT|FORK_LOG, NULL);
                if (r < 0)
                        return r;

                if (r == 0) {
                        _cleanup_close_ int parent_netns_fd = -EBADF;

                        r = namespace_open(getpid_cached(), NULL, NULL, &parent_netns_fd, NULL, NULL);
                        if (r < 0) {
                                log_error_errno(r, "Failed to open parent network namespace: %m");
                                _exit(EXIT_FAILURE);
                        }

                        r = namespace_enter(-1, -1, child_netns_fd, -1, -1);
                        if (r < 0) {
                                log_error_errno(r, "Failed to enter child network namespace: %m");
                                _exit(EXIT_FAILURE);
                        }

                        /* Reverse network interfaces pair list so that interfaces get their initial name back.
                         * This is about ensuring interfaces get their old name back when being moved back. */
                        arg_network_interfaces = strv_reverse(arg_network_interfaces);

                        r = move_network_interfaces(parent_netns_fd, arg_network_interfaces);
                        if (r < 0)
                                log_error_errno(r, "Failed to move network interfaces back to parent network namespace: %m");

                        _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
                }
        }

        r = wait_for_container(TAKE_PID(*pid), &container_status);

        /* Tell machined that we are gone. */
        if (bus)
                (void) unregister_machine(bus, arg_machine);

        if (r < 0)
                /* We failed to wait for the container, or the container exited abnormally. */
                return r;
        if (r > 0 || container_status == CONTAINER_TERMINATED) {
                /* r > 0 → The container exited with a non-zero status.
                 *         As a special case, we need to replace 133 with a different value,
                 *         because 133 is special-cased in the service file to reboot the container.
                 * otherwise → The container exited with zero status and a reboot was not requested.
                 */
                if (r == EXIT_FORCE_RESTART)
                        r = EXIT_FAILURE; /* replace 133 with the general failure code */
                *ret = r;
                return 0; /* finito */
        }

        /* CONTAINER_REBOOTED, loop again */

        if (arg_keep_unit) {
                /* Special handling if we are running as a service: instead of simply
                 * restarting the machine we want to restart the entire service, so let's
                 * inform systemd about this with the special exit code 133. The service
                 * file uses RestartForceExitStatus=133 so that this results in a full
                 * nspawn restart. This is necessary since we might have cgroup parameters
                 * set we want to have flushed out. */
                *ret = EXIT_FORCE_RESTART;
                return 0; /* finito */
        }

        expose_port_flush(&expose_args->fw_ctx, arg_expose_ports, AF_INET, &expose_args->address4);
        expose_port_flush(&expose_args->fw_ctx, arg_expose_ports, AF_INET6, &expose_args->address6);

        (void) remove_veth_links(veth_name, arg_network_veth_extra);
        *veth_created = false;
        return 1; /* loop again */
}

static int initialize_rlimits(void) {
        /* The default resource limits the kernel passes to PID 1, as per kernel 5.16. Let's pass our container payload
         * the same values as the kernel originally passed to PID 1, in order to minimize differences between host and
         * container execution environments. */

        static const struct rlimit kernel_defaults[_RLIMIT_MAX] = {
                [RLIMIT_AS]       = { RLIM_INFINITY,          RLIM_INFINITY          },
                [RLIMIT_CORE]     = { 0,                      RLIM_INFINITY          },
                [RLIMIT_CPU]      = { RLIM_INFINITY,          RLIM_INFINITY          },
                [RLIMIT_DATA]     = { RLIM_INFINITY,          RLIM_INFINITY          },
                [RLIMIT_FSIZE]    = { RLIM_INFINITY,          RLIM_INFINITY          },
                [RLIMIT_LOCKS]    = { RLIM_INFINITY,          RLIM_INFINITY          },
                [RLIMIT_MEMLOCK]  = { DEFAULT_RLIMIT_MEMLOCK, DEFAULT_RLIMIT_MEMLOCK },
                [RLIMIT_MSGQUEUE] = { 819200,                 819200                 },
                [RLIMIT_NICE]     = { 0,                      0                      },
                [RLIMIT_NOFILE]   = { 1024,                   4096                   },
                [RLIMIT_RSS]      = { RLIM_INFINITY,          RLIM_INFINITY          },
                [RLIMIT_RTPRIO]   = { 0,                      0                      },
                [RLIMIT_RTTIME]   = { RLIM_INFINITY,          RLIM_INFINITY          },
                [RLIMIT_STACK]    = { 8388608,                RLIM_INFINITY          },

                /* The kernel scales the default for RLIMIT_NPROC and RLIMIT_SIGPENDING based on the system's amount of
                 * RAM. To provide best compatibility we'll read these limits off PID 1 instead of hardcoding them
                 * here. This is safe as we know that PID 1 doesn't change these two limits and thus the original
                 * kernel's initialization should still be valid during runtime — at least if PID 1 is systemd. Note
                 * that PID 1 changes a number of other resource limits during early initialization which is why we
                 * don't read the other limits from PID 1 but prefer the static table above. */
        };

        int rl, r;

        for (rl = 0; rl < _RLIMIT_MAX; rl++) {
                /* Let's only fill in what the user hasn't explicitly configured anyway */
                if ((arg_settings_mask & (SETTING_RLIMIT_FIRST << rl)) == 0) {
                        const struct rlimit *v;
                        struct rlimit buffer;

                        if (IN_SET(rl, RLIMIT_NPROC, RLIMIT_SIGPENDING)) {
                                /* For these two let's read the limits off PID 1. See above for an explanation. */

                                r = pid_getrlimit(1, rl, &buffer);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to read resource limit RLIMIT_%s of PID 1: %m", rlimit_to_string(rl));

                                v = &buffer;
                        } else if (rl == RLIMIT_NOFILE) {
                                /* We nowadays bump RLIMIT_NOFILE's hard limit early in PID 1 for all
                                 * userspace. Given that nspawn containers are often run without our PID 1,
                                 * let's grant the containers a raised RLIMIT_NOFILE hard limit by default,
                                 * so that container userspace gets similar resources as host userspace
                                 * gets. */
                                buffer = kernel_defaults[rl];
                                buffer.rlim_max = MIN((rlim_t) read_nr_open(), (rlim_t) HIGH_RLIMIT_NOFILE);
                                v = &buffer;
                        } else
                                v = kernel_defaults + rl;

                        arg_rlimit[rl] = newdup(struct rlimit, v, 1);
                        if (!arg_rlimit[rl])
                                return log_oom();
                }

                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *k = NULL;

                        (void) rlimit_format(arg_rlimit[rl], &k);
                        log_debug("Setting RLIMIT_%s to %s.", rlimit_to_string(rl), k);
                }
        }

        return 0;
}

static int cant_be_in_netns(void) {
        _cleanup_close_ int fd = -EBADF;
        struct ucred ucred;
        int r;

        /* Check if we are in the same netns as udev. If we aren't, then device monitoring (and thus waiting
         * for loopback block devices) won't work, and we will hang. Detect this case and exit early with a
         * nice message. */

        if (!arg_image) /* only matters if --image= us used, i.e. we actually need to use loopback devices */
                return 0;

        fd = socket(AF_UNIX, SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to allocate udev control socket: %m");

        r = connect_unix_path(fd, AT_FDCWD, "/run/udev/control");
        if (r == -ENOENT || ERRNO_IS_NEG_DISCONNECT(r))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Sorry, but --image= requires access to the host's /run/ hierarchy, since we need access to udev.");
        if (r < 0)
                return log_error_errno(r, "Failed to connect socket to udev control socket: %m");

        r = getpeercred(fd, &ucred);
        if (r < 0)
                return log_error_errno(r, "Failed to determine peer of udev control socket: %m");

        r = in_same_namespace(ucred.pid, 0, NAMESPACE_NET);
        if (r < 0)
                return log_error_errno(r, "Failed to determine network namespace of udev: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Sorry, but --image= is only supported in the main network namespace, since we need access to udev/AF_NETLINK.");
        return 0;
}

static int run(int argc, char *argv[]) {
        bool remove_directory = false, remove_image = false, veth_created = false, remove_tmprootdir = false;
        _cleanup_close_ int master = -EBADF;
        _cleanup_fdset_free_ FDSet *fds = NULL;
        int r, n_fd_passed, ret = EXIT_SUCCESS;
        char veth_name[IFNAMSIZ] = "";
        struct ExposeArgs expose_args = {};
        _cleanup_(release_lock_file) LockFile tree_global_lock = LOCK_FILE_INIT, tree_local_lock = LOCK_FILE_INIT;
        char tmprootdir[] = "/tmp/nspawn-root-XXXXXX";
        _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *dissected_image = NULL;
        _cleanup_(fw_ctx_freep) FirewallContext *fw_ctx = NULL;
        pid_t pid = 0;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (geteuid() != 0) {
                r = log_warning_errno(SYNTHETIC_ERRNO(EPERM),
                                      argc >= 2 ? "Need to be root." :
                                      "Need to be root (and some arguments are usually required).\nHint: try --help");
                goto finish;
        }

        r = cant_be_in_netns();
        if (r < 0)
                goto finish;

        r = initialize_rlimits();
        if (r < 0)
                goto finish;

        r = load_oci_bundle();
        if (r < 0)
                goto finish;

        r = determine_names();
        if (r < 0)
                goto finish;

        r = load_settings();
        if (r < 0)
                goto finish;

        /* If we're not unsharing the network namespace and are unsharing the user namespace, we won't have
         * permissions to bind ports in the container, so let's drop the CAP_NET_BIND_SERVICE capability to
         * indicate that. */
        if (!arg_private_network && arg_userns_mode != USER_NAMESPACE_NO && arg_uid_shift > 0)
                arg_caps_retain &= ~(UINT64_C(1) << CAP_NET_BIND_SERVICE);

        r = cg_unified();
        if (r < 0) {
                log_error_errno(r, "Failed to determine whether the unified cgroups hierarchy is used: %m");
                goto finish;
        }

        r = verify_arguments();
        if (r < 0)
                goto finish;

        r = verify_network_interfaces_initialized();
        if (r < 0)
                goto finish;

        /* Reapply environment settings. */
        (void) detect_unified_cgroup_hierarchy_from_environment();

        /* Ignore SIGPIPE here, because we use splice() on the ptyfwd stuff and that will generate SIGPIPE if
         * the result is closed. Note that the container payload child will reset signal mask+handler anyway,
         * so just turning this off here means we only turn it off in nspawn itself, not any children. */
        (void) ignore_signals(SIGPIPE);

        n_fd_passed = sd_listen_fds(false);
        if (n_fd_passed > 0) {
                r = fdset_new_listen_fds(&fds, false);
                if (r < 0) {
                        log_error_errno(r, "Failed to collect file descriptors: %m");
                        goto finish;
                }
        }

        /* The "default" umask. This is appropriate for most file and directory
        * operations performed by nspawn, and is the umask that will be used for
        * the child. Functions like copy_devnodes() change the umask temporarily. */
        umask(0022);

        if (arg_directory) {
                assert(!arg_image);

                /* Safety precaution: let's not allow running images from the live host OS image, as long as
                 * /var from the host will propagate into container dynamically (because bad things happen if
                 * two systems write to the same /var). Let's allow it for the special cases where /var is
                 * either copied (i.e. --ephemeral) or replaced (i.e. --volatile=yes|state). */
                if (path_equal(arg_directory, "/") && !(arg_ephemeral || IN_SET(arg_volatile_mode, VOLATILE_YES, VOLATILE_STATE))) {
                        r = log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                            "Spawning container on root directory is not supported. Consider using --ephemeral, --volatile=yes or --volatile=state.");
                        goto finish;
                }

                if (arg_ephemeral) {
                        _cleanup_free_ char *np = NULL;

                        r = chase_and_update(&arg_directory, 0);
                        if (r < 0)
                                goto finish;

                        /* If the specified path is a mount point we generate the new snapshot immediately
                         * inside it under a random name. However if the specified is not a mount point we
                         * create the new snapshot in the parent directory, just next to it. */
                        r = path_is_mount_point(arg_directory, NULL, 0);
                        if (r < 0) {
                                log_error_errno(r, "Failed to determine whether directory %s is mount point: %m", arg_directory);
                                goto finish;
                        }
                        if (r > 0)
                                r = tempfn_random_child(arg_directory, "machine.", &np);
                        else
                                r = tempfn_random(arg_directory, "machine.", &np);
                        if (r < 0) {
                                log_error_errno(r, "Failed to generate name for directory snapshot: %m");
                                goto finish;
                        }

                        /* We take an exclusive lock on this image, since it's our private, ephemeral copy
                         * only owned by us and no one else. */
                        r = image_path_lock(np, LOCK_EX|LOCK_NB, &tree_global_lock, &tree_local_lock);
                        if (r < 0) {
                                log_error_errno(r, "Failed to lock %s: %m", np);
                                goto finish;
                        }

                        {
                                BLOCK_SIGNALS(SIGINT);
                                r = btrfs_subvol_snapshot_at(AT_FDCWD, arg_directory, AT_FDCWD, np,
                                                             (arg_read_only ? BTRFS_SNAPSHOT_READ_ONLY : 0) |
                                                             BTRFS_SNAPSHOT_FALLBACK_COPY |
                                                             BTRFS_SNAPSHOT_FALLBACK_DIRECTORY |
                                                             BTRFS_SNAPSHOT_RECURSIVE |
                                                             BTRFS_SNAPSHOT_QUOTA |
                                                             BTRFS_SNAPSHOT_SIGINT);
                        }
                        if (r == -EINTR) {
                                log_error_errno(r, "Interrupted while copying file system tree to %s, removed again.", np);
                                goto finish;
                        }
                        if (r < 0) {
                                log_error_errno(r, "Failed to create snapshot %s from %s: %m", np, arg_directory);
                                goto finish;
                        }

                        free_and_replace(arg_directory, np);
                        remove_directory = true;
                } else {
                        r = chase_and_update(&arg_directory, arg_template ? CHASE_NONEXISTENT : 0);
                        if (r < 0)
                                goto finish;

                        r = image_path_lock(arg_directory, (arg_read_only ? LOCK_SH : LOCK_EX) | LOCK_NB, &tree_global_lock, &tree_local_lock);
                        if (r == -EBUSY) {
                                log_error_errno(r, "Directory tree %s is currently busy.", arg_directory);
                                goto finish;
                        }
                        if (r < 0) {
                                log_error_errno(r, "Failed to lock %s: %m", arg_directory);
                                goto finish;
                        }

                        if (arg_template) {
                                r = chase_and_update(&arg_template, 0);
                                if (r < 0)
                                        goto finish;

                                {
                                        BLOCK_SIGNALS(SIGINT);
                                        r = btrfs_subvol_snapshot_at(AT_FDCWD, arg_template, AT_FDCWD, arg_directory,
                                                                     (arg_read_only ? BTRFS_SNAPSHOT_READ_ONLY : 0) |
                                                                     BTRFS_SNAPSHOT_FALLBACK_COPY |
                                                                     BTRFS_SNAPSHOT_FALLBACK_DIRECTORY |
                                                                     BTRFS_SNAPSHOT_FALLBACK_IMMUTABLE |
                                                                     BTRFS_SNAPSHOT_RECURSIVE |
                                                                     BTRFS_SNAPSHOT_QUOTA |
                                                                     BTRFS_SNAPSHOT_SIGINT);
                                }
                                if (r == -EEXIST)
                                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                                 "Directory %s already exists, not populating from template %s.", arg_directory, arg_template);
                                else if (r == -EINTR) {
                                        log_error_errno(r, "Interrupted while copying file system tree to %s, removed again.", arg_directory);
                                        goto finish;
                                } else if (r < 0) {
                                        log_error_errno(r, "Couldn't create snapshot %s from %s: %m", arg_directory, arg_template);
                                        goto finish;
                                } else
                                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                                 "Populated %s from template %s.", arg_directory, arg_template);
                        }
                }

                if (arg_start_mode == START_BOOT) {
                        _cleanup_free_ char *b = NULL;
                        const char *p;
                        int check_os_release, is_os_tree;

                        if (arg_pivot_root_new) {
                                b = path_join(arg_directory, arg_pivot_root_new);
                                if (!b) {
                                        r = log_oom();
                                        goto finish;
                                }

                                p = b;
                        } else
                                p = arg_directory;

                        check_os_release = getenv_bool("SYSTEMD_NSPAWN_CHECK_OS_RELEASE");
                        if (check_os_release < 0 && check_os_release != -ENXIO) {
                                r = log_error_errno(check_os_release, "Failed to parse $SYSTEMD_NSPAWN_CHECK_OS_RELEASE: %m");
                                goto finish;
                        }

                        is_os_tree = path_is_os_tree(p);
                        if (is_os_tree == 0 && check_os_release == 0)
                                log_debug("Directory %s is missing an os-release file, continuing anyway.", p);
                        else if (is_os_tree <= 0) {
                                r = log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                    "Directory %s doesn't look like an OS root directory (os-release file is missing). Refusing.", p);
                                goto finish;
                        }
                } else {
                        _cleanup_free_ char *p = NULL;

                        if (arg_pivot_root_new)
                                p = path_join(arg_directory, arg_pivot_root_new, "/usr/");
                        else
                                p = path_join(arg_directory, "/usr/");
                        if (!p) {
                                r = log_oom();
                                goto finish;
                        }

                        if (laccess(p, F_OK) < 0) {
                                r = log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                    "Directory %s doesn't look like it has an OS tree (/usr/ directory is missing). Refusing.", arg_directory);
                                goto finish;
                        }
                }

        } else {
                DissectImageFlags dissect_image_flags =
                        DISSECT_IMAGE_GENERIC_ROOT |
                        DISSECT_IMAGE_REQUIRE_ROOT |
                        DISSECT_IMAGE_RELAX_VAR_CHECK |
                        DISSECT_IMAGE_USR_NO_ROOT |
                        DISSECT_IMAGE_ADD_PARTITION_DEVICES |
                        DISSECT_IMAGE_PIN_PARTITION_DEVICES;
                assert(arg_image);
                assert(!arg_template);

                r = chase_and_update(&arg_image, 0);
                if (r < 0)
                        goto finish;

                if (arg_ephemeral)  {
                        _cleanup_free_ char *np = NULL;

                        r = tempfn_random(arg_image, "machine.", &np);
                        if (r < 0) {
                                log_error_errno(r, "Failed to generate name for image snapshot: %m");
                                goto finish;
                        }

                        /* Always take an exclusive lock on our own ephemeral copy. */
                        r = image_path_lock(np, LOCK_EX|LOCK_NB, &tree_global_lock, &tree_local_lock);
                        if (r < 0) {
                                log_error_errno(r, "Failed to create image lock: %m");
                                goto finish;
                        }

                        {
                                BLOCK_SIGNALS(SIGINT);
                                r = copy_file_full(arg_image, np, O_EXCL, arg_read_only ? 0400 : 0600,
                                                   FS_NOCOW_FL, FS_NOCOW_FL,
                                                   COPY_REFLINK|COPY_CRTIME|COPY_SIGINT,
                                                   NULL, NULL);
                        }
                        if (r == -EINTR) {
                                log_error_errno(r, "Interrupted while copying image file to %s, removed again.", np);
                                goto finish;
                        }
                        if (r < 0) {
                                r = log_error_errno(r, "Failed to copy image file: %m");
                                goto finish;
                        }

                        free_and_replace(arg_image, np);
                        remove_image = true;
                } else {
                        r = image_path_lock(arg_image, (arg_read_only ? LOCK_SH : LOCK_EX) | LOCK_NB, &tree_global_lock, &tree_local_lock);
                        if (r == -EBUSY) {
                                log_error_errno(r, "Disk image %s is currently busy.", arg_image);
                                goto finish;
                        }
                        if (r < 0) {
                                log_error_errno(r, "Failed to create image lock: %m");
                                goto finish;
                        }

                        r = verity_settings_load(
                                        &arg_verity_settings,
                                        arg_image, NULL, NULL);
                        if (r < 0) {
                                log_error_errno(r, "Failed to read verity artefacts for %s: %m", arg_image);
                                goto finish;
                        }

                        if (arg_verity_settings.data_path)
                                dissect_image_flags |= DISSECT_IMAGE_NO_PARTITION_TABLE;
                }

                if (!mkdtemp(tmprootdir)) {
                        r = log_error_errno(errno, "Failed to create temporary directory: %m");
                        goto finish;
                }

                remove_tmprootdir = true;

                arg_directory = strdup(tmprootdir);
                if (!arg_directory) {
                        r = log_oom();
                        goto finish;
                }

                r = loop_device_make_by_path(
                                arg_image,
                                arg_read_only ? O_RDONLY : O_RDWR,
                                /* sector_size= */ UINT32_MAX,
                                FLAGS_SET(dissect_image_flags, DISSECT_IMAGE_NO_PARTITION_TABLE) ? 0 : LO_FLAGS_PARTSCAN,
                                LOCK_SH,
                                &loop);
                if (r < 0) {
                        log_error_errno(r, "Failed to set up loopback block device: %m");
                        goto finish;
                }

                r = dissect_loop_device_and_warn(
                                loop,
                                &arg_verity_settings,
                                /* mount_options=*/ NULL,
                                arg_image_policy ?: &image_policy_container,
                                dissect_image_flags,
                                &dissected_image);
                if (r == -ENOPKG) {
                        /* dissected_image_and_warn() already printed a brief error message. Extend on that with more details */
                        log_notice("Note that the disk image needs to\n"
                                   "    a) either contain only a single MBR partition of type 0x83 that is marked bootable\n"
                                   "    b) or contain a single GPT partition of type 0FC63DAF-8483-4772-8E79-3D69D8477DE4\n"
                                   "    c) or follow https://uapi-group.org/specifications/specs/discoverable_partitions_specification\n"
                                   "    d) or contain a file system without a partition table\n"
                                   "in order to be bootable with systemd-nspawn.");
                        goto finish;
                }
                if (r < 0)
                        goto finish;

                r = dissected_image_load_verity_sig_partition(
                                dissected_image,
                                loop->fd,
                                &arg_verity_settings);
                if (r < 0)
                        goto finish;

                if (dissected_image->has_verity && !arg_verity_settings.root_hash && !dissected_image->has_verity_sig)
                        log_notice("Note: image %s contains verity information, but no root hash specified and no embedded "
                                   "root hash signature found! Proceeding without integrity checking.", arg_image);

                r = dissected_image_decrypt_interactively(
                                dissected_image,
                                NULL,
                                &arg_verity_settings,
                                0);
                if (r < 0)
                        goto finish;

                /* Now that we mounted the image, let's try to remove it again, if it is ephemeral */
                if (remove_image && unlink(arg_image) >= 0)
                        remove_image = false;

                if (arg_architecture < 0)
                        arg_architecture = dissected_image_architecture(dissected_image);
        }

        r = custom_mount_prepare_all(arg_directory, arg_custom_mounts, arg_n_custom_mounts);
        if (r < 0)
                goto finish;

        if (arg_console_mode < 0)
                arg_console_mode =
                        isatty(STDIN_FILENO) > 0 &&
                        isatty(STDOUT_FILENO) > 0 ? CONSOLE_INTERACTIVE : CONSOLE_READ_ONLY;

        if (arg_console_mode == CONSOLE_PIPE) /* if we pass STDERR on to the container, don't add our own logs into it too */
                arg_quiet = true;

        if (!arg_quiet)
                log_info("Spawning container %s on %s.\nPress Ctrl-] three times within 1s to kill container.",
                         arg_machine, arg_image ?: arg_directory);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD, SIGWINCH, SIGTERM, SIGINT, SIGRTMIN+18, -1) >= 0);

        r = make_reaper_process(true);
        if (r < 0) {
                log_error_errno(r, "Failed to become subreaper: %m");
                goto finish;
        }

        if (arg_expose_ports) {
                r = fw_ctx_new(&fw_ctx);
                if (r < 0) {
                        log_error_errno(r, "Cannot expose configured ports, firewall initialization failed: %m");
                        goto finish;
                }
                expose_args.fw_ctx = fw_ctx;
        }
        for (;;) {
                r = run_container(dissected_image,
                                  fds,
                                  veth_name, &veth_created,
                                  &expose_args, &master,
                                  &pid, &ret);
                if (r <= 0)
                        break;
        }

finish:
        (void) sd_notify(false,
                         r == 0 && ret == EXIT_FORCE_RESTART ? "STOPPING=1\nSTATUS=Restarting..." :
                                                               "STOPPING=1\nSTATUS=Terminating...");

        if (pid > 0)
                (void) kill(pid, SIGKILL);

        /* Try to flush whatever is still queued in the pty */
        if (master >= 0) {
                (void) copy_bytes(master, STDOUT_FILENO, UINT64_MAX, 0);
                master = safe_close(master);
        }

        if (pid > 0)
                (void) wait_for_terminate(pid, NULL);

        pager_close();

        if (remove_directory && arg_directory) {
                int k;

                k = rm_rf(arg_directory, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);
                if (k < 0)
                        log_warning_errno(k, "Cannot remove '%s', ignoring: %m", arg_directory);
        }

        if (remove_image && arg_image) {
                if (unlink(arg_image) < 0)
                        log_warning_errno(errno, "Can't remove image file '%s', ignoring: %m", arg_image);
        }

        if (remove_tmprootdir) {
                if (rmdir(tmprootdir) < 0)
                        log_debug_errno(errno, "Can't remove temporary root directory '%s', ignoring: %m", tmprootdir);
        }

        if (arg_machine) {
                const char *p;

                p = strjoina("/run/systemd/nspawn/propagate/", arg_machine);
                (void) rm_rf(p, REMOVE_ROOT);
        }

        expose_port_flush(&fw_ctx, arg_expose_ports, AF_INET,  &expose_args.address4);
        expose_port_flush(&fw_ctx, arg_expose_ports, AF_INET6, &expose_args.address6);

        if (veth_created)
                (void) remove_veth_links(veth_name, arg_network_veth_extra);
        (void) remove_bridge(arg_network_zone);

        custom_mount_free_all(arg_custom_mounts, arg_n_custom_mounts);
        expose_port_free_all(arg_expose_ports);
        rlimit_free_all(arg_rlimit);
        device_node_array_free(arg_extra_nodes, arg_n_extra_nodes);

        if (r < 0)
                return r;

        return ret;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
