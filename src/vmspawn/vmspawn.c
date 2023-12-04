/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "architecture.h"
#include "build.h"
#include "common-signal.h"
#include "copy.h"
#include "creds-util.h"
#include "escape.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "log.h"
#include "machine-credential.h"
#include "macro.h"
#include "main-func.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "sd-daemon.h"
#include "sd-event.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "unit-name.h"
#include "vmspawn-scope.h"
#include "vmspawn-settings.h"
#include "vmspawn-util.h"

static PagerFlags arg_pager_flags = 0;
static char *arg_directory = NULL;
static char *arg_image = NULL;
static char *arg_machine = NULL;
static char *arg_qemu_smp = NULL;
static uint64_t arg_qemu_mem = 2ULL * 1024ULL * 1024ULL * 1024ULL;
static int arg_qemu_kvm = -1;
static int arg_qemu_vsock = -1;
static uint64_t arg_vsock_cid = UINT64_MAX;
static int arg_vtpm = -1;
static char *arg_kernel = NULL;
static char **arg_initrds = NULL;
static bool arg_qemu_gui = false;
static QemuNetworkStack arg_qemu_net = QEMU_NET_USER;
static int arg_secure_boot = -1;
static MachineCredentialContext arg_credentials = {};
static SettingsMask arg_settings_mask = 0;
static char **arg_kernel_cmdline_extra = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_directory, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_machine, freep);
STATIC_DESTRUCTOR_REGISTER(arg_qemu_smp, freep);
STATIC_DESTRUCTOR_REGISTER(arg_credentials, machine_credential_context_done);
STATIC_DESTRUCTOR_REGISTER(arg_kernel, freep);
STATIC_DESTRUCTOR_REGISTER(arg_initrds, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_kernel_cmdline_extra, strv_freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("systemd-vmspawn", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] [ARGUMENTS...]\n\n"
               "%5$sSpawn a command or OS in a virtual machine.%6$s\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Print version string\n"
               "     --no-pager             Do not pipe output into a pager\n\n"
               "%3$sImage:%4$s\n"
               "  -D --directory=PATH       Root directory for the container\n"
               "  -i --image=PATH           Root file system disk image (or device node) for\n"
               "                            the virtual machine\n\n"
               "%3$sSystem Identity:%4$s\n"
               "  -M --machine=NAME         Set the machine name for the container\n\n"
               "%3$sHost Configuration:%4$s\n"
               "     --qemu-smp=SMP         Configure guest's SMP settings\n"
               "     --qemu-mem=MEM         Configure guest's RAM size\n"
               "     --qemu-kvm=BOOL        Configure whether to use KVM or not\n"
               "     --qemu-vsock=BOOL      Configure whether to use qemu with a vsock or not\n"
               "     --vsock-cid=           Specify the CID to use for the qemu guest's vsock\n"
               "     --vtpm=BOOL            Configure whether to use a virtual TPM or not\n"
               "     --kernel=PATH          Specify the kernel for direct kernel boot\n"
               "     --initrd=PATH          Specify the initrd for direct kernel boot\n"
               "     --qemu-gui             Start QEMU in graphical mode\n"
               "     --qemu-net=user|tap|none\n"
               "                            Configure QEMU's networking stack\n"
               "     --secure-boot=BOOL     Configure whether to search for firmware which\n"
               "                            supports Secure Boot\n\n"
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

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_QEMU_SMP,
                ARG_QEMU_MEM,
                ARG_QEMU_KVM,
                ARG_QEMU_VSOCK,
                ARG_VSOCK_CID,
                ARG_VTPM,
                ARG_KERNEL,
                ARG_INITRD,
                ARG_QEMU_GUI,
                ARG_QEMU_NET,
                ARG_SECURE_BOOT,
                ARG_SET_CREDENTIAL,
                ARG_LOAD_CREDENTIAL,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                { "image",           required_argument, NULL, 'i'                 },
                { "directory",       required_argument, NULL, 'D'                 },
                { "machine",         required_argument, NULL, 'M'                 },
                { "qemu-smp",        required_argument, NULL, ARG_QEMU_SMP        },
                { "qemu-mem",        required_argument, NULL, ARG_QEMU_MEM        },
                { "qemu-kvm",        required_argument, NULL, ARG_QEMU_KVM        },
                { "qemu-vsock",      required_argument, NULL, ARG_QEMU_VSOCK      },
                { "vsock-cid",       required_argument, NULL, ARG_VSOCK_CID       },
                { "vtpm",            required_argument, NULL, ARG_VTPM            },
                { "kernel",          required_argument, NULL, ARG_KERNEL          },
                { "initrd",          required_argument, NULL, ARG_INITRD          },
                { "qemu-gui",        no_argument,       NULL, ARG_QEMU_GUI        },
                { "qemu-net",        required_argument, NULL, ARG_QEMU_NET        },
                { "secure-boot",     required_argument, NULL, ARG_SECURE_BOOT     },
                { "set-credential",  required_argument, NULL, ARG_SET_CREDENTIAL  },
                { "load-credential", required_argument, NULL, ARG_LOAD_CREDENTIAL },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        optind = 0;
        while ((c = getopt_long(argc, argv, "+hD:i:M", options, NULL)) >= 0)
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

                case 'i':
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;

                        arg_settings_mask |= SETTING_DIRECTORY;
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

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_QEMU_SMP:
                        r = free_and_strdup_warn(&arg_qemu_smp, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_QEMU_MEM:
                        r = parse_size(optarg, 1024, &arg_qemu_mem);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --qemu-mem=%s: %m", optarg);
                        break;

                case ARG_QEMU_KVM:
                        r = parse_tristate(optarg, &arg_qemu_kvm);
                        if (r < 0)
                            return log_error_errno(r, "Failed to parse --qemu-kvm=%s: %m", optarg);
                        break;

                case ARG_QEMU_VSOCK:
                        r = parse_tristate(optarg, &arg_qemu_vsock);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --qemu-vsock=%s: %m", optarg);
                        break;

                case ARG_VSOCK_CID: {
                        unsigned cid;
                        if (isempty(optarg))
                                cid = VMADDR_CID_ANY;
                        else {
                                r = safe_atou_bounded(optarg, 3, UINT_MAX - 1, &cid);
                                if (r == -ERANGE)
                                        return log_error_errno(r, "Invalid value for --vsock-cid=: %m");
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse --vsock-cid=%s: %m", optarg);
                        }
                        arg_vsock_cid = (uint64_t)cid;
                        break;
                }

                case ARG_VTPM:
                        r = parse_tristate(optarg, &arg_vtpm);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --vtpm=%s: %m", optarg);
                        break;

                case ARG_KERNEL:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_kernel);
                        if (r < 0)
                                return r;
                        break;

                case ARG_INITRD: {
                        _cleanup_free_ char *initrd = NULL;
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &initrd);
                        if (r < 0)
                                return r;

                        r = strv_push(&arg_initrds, TAKE_PTR(initrd));
                        if (r < 0)
                                return log_oom();
                        break;
                }

                case ARG_QEMU_GUI:
                        arg_qemu_gui = true;
                        break;

                case ARG_QEMU_NET:
                        arg_qemu_net = parse_qemu_network_stack(optarg);
                        if (arg_qemu_net == _QEMU_NET_INVALID)
                                return log_error_errno(r, "Failed to parse --qemu-net=%s: %m", optarg);
                        break;

                case ARG_SECURE_BOOT:
                        r = parse_tristate(optarg, &arg_secure_boot);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --secure-boot=%s: %m", optarg);
                        break;

                case ARG_SET_CREDENTIAL: {
                        r = machine_credential_set(&arg_credentials, optarg);
                        if (r < 0)
                                return r;
                        arg_settings_mask |= SETTING_CREDENTIALS;
                        break;
                }

                case ARG_LOAD_CREDENTIAL: {
                        r = machine_credential_load(&arg_credentials, optarg);
                        if (r < 0)
                                return r;

                        arg_settings_mask |= SETTING_CREDENTIALS;
                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (argc > optind) {
                strv_free(arg_kernel_cmdline_extra);
                arg_kernel_cmdline_extra = strv_copy(argv + optind);
                if (!arg_kernel_cmdline_extra)
                        return log_oom();

                arg_settings_mask |= SETTING_START_MODE;
        }

        return 1;
}

static int open_vsock(void) {
        _cleanup_close_ int vsock_fd = -EBADF;
        int r;
        static const union sockaddr_union bind_addr = {
                .vm.svm_family = AF_VSOCK,
                .vm.svm_cid = VMADDR_CID_ANY,
                .vm.svm_port = VMADDR_PORT_ANY,
        };

        vsock_fd = socket(AF_VSOCK, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (vsock_fd < 0)
                return log_error_errno(errno, "Failed to open AF_VSOCK socket: %m");

        r = bind(vsock_fd, &bind_addr.sa, sizeof(bind_addr.vm));
        if (r < 0)
                return log_error_errno(errno, "Failed to bind to vsock to address %u:%u: %m", bind_addr.vm.svm_cid, bind_addr.vm.svm_port);

        r = listen(vsock_fd, SOMAXCONN_DELUXE);
        if (r < 0)
                return log_error_errno(errno, "Failed to listen on vsock: %m");

        return TAKE_FD(vsock_fd);
}

static int vmspawn_dispatch_notify_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        char buf[NOTIFY_BUFFER_MAX+1];
        const char *p = NULL;
        struct iovec iovec = {
                .iov_base = buf,
                .iov_len = sizeof(buf)-1,
        };
        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
        };
        ssize_t n;
        _cleanup_strv_free_ char **tags = NULL;
        int r, *exit_status = ASSERT_PTR(userdata);

        n = recvmsg_safe(fd, &msghdr, MSG_DONTWAIT);
        if (ERRNO_IS_NEG_TRANSIENT(n))
                return 0;
        if (n == -EXFULL) {
                log_warning_errno(n, "Got message with truncated control data, ignoring: %m");
                return 0;
        }
        if (n < 0)
                return log_warning_errno(n, "Couldn't read notification socket: %m");

        if ((size_t) n >= sizeof(buf)) {
                log_warning("Received notify message exceeded maximum size. Ignoring.");
                return 0;
        }

        buf[n] = 0;
        tags = strv_split(buf, "\n\r");
        if (!tags)
                return log_oom();

        STRV_FOREACH(s, tags)
                log_debug("Received tag %s from notify socket", *s);

        if (strv_contains(tags, "READY=1")) {
                r = sd_notify(false, "READY=1\n");
                if (r < 0)
                        log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");
        }

        p = strv_find_startswith(tags, "STATUS=");
        if (p)
                (void) sd_notifyf(false, "STATUS=VM running: %s", p);

        p = strv_find_startswith(tags, "EXIT_STATUS=");
        if (p) {
                r = safe_atoi(p, exit_status);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse exit status from %s, ignoring: %m", p);
        }

        /* we will only receive one message from each connection so disable this source once one is received */
        source = sd_event_source_disable_unref(source);

        return 0;
}

static int vmspawn_dispatch_vsock_connections(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        int r;
        sd_event *event;
        _cleanup_close_ int conn_fd = -EBADF;

        assert(userdata);

        if (revents != EPOLLIN) {
                log_warning("Got unexpected poll event for vsock fd.");
                return 0;
        }

        conn_fd = accept4(fd, NULL, NULL, SOCK_CLOEXEC|SOCK_NONBLOCK);
        if (conn_fd < 0) {
                log_warning_errno(errno, "Failed to accept connection from vsock fd (%m), ignoring...");
                return 0;
        }

        event = sd_event_source_get_event(source);
        if (!event)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Failed to retrieve event from event source, exiting task");

        /* add a new floating task to read from the connection */
        r = sd_event_add_io(event, NULL, conn_fd, revents, vmspawn_dispatch_notify_fd, userdata);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate notify connection event source: %m");

        /* conn_fd is now owned by the event loop so don't clean it up */
        TAKE_FD(conn_fd);

        return 0;
}

static int setup_notify_parent(sd_event *event, int fd, int *exit_status, sd_event_source **notify_event_source) {
        int r;

        r = sd_event_add_io(event, notify_event_source, fd, EPOLLIN, vmspawn_dispatch_vsock_connections, exit_status);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate notify socket event source: %m");

        (void) sd_event_source_set_description(*notify_event_source, "vmspawn-notify-sock");

        return 0;
}

static int on_orderly_shutdown(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        pid_t pid;

        pid = PTR_TO_PID(userdata);
        if (pid > 0) {
                /* TODO: actually talk to qemu and ask the guest to shutdown here */
                if (kill(pid, SIGKILL) >= 0) {
                        log_info("Trying to halt qemu. Send SIGTERM again to trigger vmspawn to immediately terminate.");
                        sd_event_source_set_userdata(s, NULL);
                        return 0;
                }
        }

        sd_event_exit(sd_event_source_get_event(s), 0);
        return 0;
}

static int on_child_exit(sd_event_source *s, const siginfo_t *si, void *userdata) {
        sd_event_exit(sd_event_source_get_event(s), 0);
        return 0;
}

static int cmdline_add_vsock(char ***cmdline, int vsock_fd) {
        int r;

        r = strv_extend(cmdline, "-smbios");
        if (r < 0)
                return r;

        union sockaddr_union addr;
        socklen_t addr_len = sizeof addr.vm;
        r = getsockname(vsock_fd, &addr.sa, &addr_len);
        if (r < 0)
                return -errno;
        assert(addr_len >= sizeof addr.vm);
        assert(addr.vm.svm_family == AF_VSOCK);

        r = strv_extendf(cmdline, "type=11,value=io.systemd.credential:vmm.notify_socket=vsock-stream:%u:%u", (unsigned) VMADDR_CID_HOST, addr.vm.svm_port);
        if (r < 0)
                return r;

        return 0;
}

static int start_vtpm(sd_bus *bus, const char *scope, const char *vtpm, const char **ret_state_tempdir) {
        _cleanup_(rm_rf_physical_and_freep) char *state = NULL;
        _cleanup_strv_free_ char **cmdline = NULL, **cleanup = NULL;
        _cleanup_free_ char *sock_path = NULL, *rm_path = NULL, *unit_name = NULL;
        int r;

        assert(bus);
        assert(scope);
        assert(vtpm);
        assert(ret_state_tempdir);

        r = mkdtemp_malloc("/tmp/vmspawn-vtpm-XXXXXX", &state);
        if (r < 0)
                return r;

        sock_path = strjoin(state, "/sock");
        if (!sock_path)
                return log_oom();

        cmdline = strv_new(vtpm, "socket", "--tpm2", "--tpmstate");
        if (!cmdline)
                return log_oom();

        r = strv_extendf(&cmdline, "dir=%s", state);
        if (r < 0)
                return log_oom();

        r = strv_extend_strv(&cmdline, STRV_MAKE("--ctrl", "type=unixio,fd=3"), /* filter_duplicates= */ false);
        if (r < 0)
                return log_oom();

        r = find_executable("rm", &rm_path);
        if (r < 0)
                return log_error_errno(r, "Failed to find 'rm' binary: %m");

        cleanup = strv_new(rm_path, "-rf", state);
        if (!cleanup)
                return log_oom();

        unit_name = strjoin(scope, "-vtpm");
        if (!unit_name)
                return log_oom();

        r = attach_command_to_socket_in_scope(bus, scope, unit_name, sock_path, SOCK_STREAM, cmdline, cleanup, NULL);
        if (r < 0)
                return r;

        *ret_state_tempdir = TAKE_PTR(state);

        return 0;
}

static int find_initrd(char *kernel, char **ret_initrd) {
        _cleanup_free_ char *s = NULL, *initrd = NULL;
        char *c;

        assert(ret_initrd);

        /* if the kernel is an EFI image we don't need an initrd */
        if (endswith(kernel, ".efi")) {
                ret_initrd = NULL;
                return 0;
        }

        /* try in order:
         *   1. kernel + .initrd
         *   2. kernel stripped of suffix + .initrd
         *   3. image + .initrd
         */
        initrd = strjoin(kernel, ".initrd");
        if (!initrd)
                return log_oom();

        if (access(initrd, F_OK) >= 0) {
                *ret_initrd = TAKE_PTR(initrd);
                return 0;
        }
        if (errno != ENOENT)
                return log_error_errno(errno, "Encountered error searching for initrd: %m");
        initrd = mfree(initrd);

        /* strip kernel suffix */
        s = strdup(kernel);
        if (!s)
                return log_oom();

        c = strrchr(s, '.');
        if (c)
                *c = '\0';

        initrd = strjoin(s, ".initrd");
        if (!initrd)
                return log_oom();
        if (access(initrd, F_OK) >= 0) {
                *ret_initrd = TAKE_PTR(initrd);
                return 0;
        }
        if (errno != ENOENT)
                return log_error_errno(errno, "Encountered error searching for initrd: %m");
        initrd = mfree(initrd);

        initrd = strjoin(arg_image ?: arg_directory, ".initrd");
        if (!initrd)
                return log_oom();
        if (access(initrd, F_OK) >= 0) {
                *ret_initrd = TAKE_PTR(initrd);
                return 0;
        }
        if (errno != ENOENT)
                return log_error_errno(errno, "Encountered error searching for initrd: %m");

        return -ENOENT;
}

static int start_virtiofsd(sd_bus *bus, const char *scope, const char *directory, char **ret_state_tempdir, char **ret_sock_name) {
        _cleanup_(rm_rf_physical_and_freep) char *state = NULL;
        _cleanup_strv_free_ char **cmdline = NULL, **cleanup = NULL;
        _cleanup_free_ char *virtiofsd = NULL, *sock_path = NULL, *sock_name = NULL, *rm_path = NULL, *unit_name = NULL;
        int r;

        assert(bus);
        assert(scope);
        assert(directory);
        assert(ret_state_tempdir);
        assert(ret_sock_name);

        r = find_executable("virtiofsd", &virtiofsd);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Error while searching for virtiofsd: %m");

        if (!virtiofsd) {
                FOREACH_STRING(dir, "/usr/libexec/virtiofsd", "/usr/libexec/virtiofsd") {
                        if (access(dir, X_OK) >= 0) {
                                virtiofsd = strdup(dir);
                                if (!virtiofsd)
                                        return log_oom();
                                break;
                        }

                        if (!IN_SET(errno, ENOENT, EACCES))
                                return log_error_errno(errno, "Error while searching for virtiofsd: %m");
                }
        }

        if (!virtiofsd)
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "Failed to find virtiofsd binary.");

        r = find_executable("rm", &rm_path);
        if (r < 0)
                return log_error_errno(r, "Failed to find 'rm' binary: %m");

        r = mkdtemp_malloc("/tmp/vmspawn-virtiofsd-XXXXXX", &state);
        if (r < 0)
                return r;

        if (asprintf(&sock_name, "sock-%"PRIx64, random_u64()) < 0)
                return log_oom();

        sock_path = strjoin(state, "/", sock_name);
        if (!sock_path)
                return log_oom();

        cmdline = strv_new(virtiofsd, "--shared-dir", directory, "--xattr", "--posix-acl", "--fd", "3");
        if (!cmdline)
                return log_oom();

        cleanup = strv_new(rm_path, "-rf", state);
        if (!cleanup)
                return log_oom();

        unit_name = strjoin(scope, "-virtiofsd", directory);
        if (!unit_name)
                return log_oom();

        r = attach_command_to_socket_in_scope(bus, scope, unit_name, sock_path, SOCK_STREAM, cmdline, cleanup, NULL);
        if (r < 0)
                return r;

        *ret_state_tempdir = TAKE_PTR(state);
        *ret_sock_name = TAKE_PTR(sock_name);

        return 0;
}

static int run_virtual_machine(int kvm_device_fd, int vhost_device_fd) {
        _cleanup_(ovmf_config_freep) OvmfConfig *ovmf_config = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *machine = NULL, *qemu_binary = NULL, *mem = NULL, *trans_scope = NULL,
                            *kernel = NULL;
        _cleanup_close_ int notify_sock_fd = -EBADF;
        _cleanup_strv_free_ char **cmdline = NULL;
        _cleanup_free_ int *pass_fds = NULL;
        size_t n_pass_fds = 0;
        const char *accel, *shm;
        int r;

        if (getuid() == 0)
                r = sd_bus_open_system(&bus);
        else
                r = sd_bus_open_user(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to systemd bus: %m");

        r = start_transient_scope(bus, arg_machine, /* allow_pidfd= */ true, &trans_scope);
        if (r < 0)
                return r;

        bool use_kvm = arg_qemu_kvm > 0;
        if (arg_qemu_kvm < 0) {
                r = qemu_check_kvm_support();
                if (r < 0)
                        return log_error_errno(r, "Failed to check for KVM support: %m");
                use_kvm = r;
        }

        r = find_ovmf_config(arg_secure_boot, &ovmf_config);
        if (r < 0)
                return log_error_errno(r, "Failed to find OVMF config: %m");

        /* only warn if the user hasn't disabled secureboot */
        if (!ovmf_config->supports_sb && arg_secure_boot)
                log_warning("Couldn't find OVMF firmware blob with Secure Boot support, "
                            "falling back to OVMF firmware blobs without Secure Boot support.");

        shm = arg_directory ? ",memory-backend=mem" : "";
        if (IN_SET(native_architecture(), ARCHITECTURE_ARM64, ARCHITECTURE_ARM64_BE))
                machine = strjoin("type=virt", shm);
        else
                machine = strjoin("type=q35,smm=", on_off(ovmf_config->supports_sb), shm);
        if (!machine)
                return log_oom();

        if (arg_kernel) {
                if (access(arg_kernel, F_OK) < 0)
                        return log_error_errno(errno, "Kernel not found at %s: %m", arg_kernel);
                kernel = strdup(arg_kernel);
                if (!kernel)
                        return log_oom();
        } else if (arg_directory) {
                kernel = strjoin(arg_directory, ".vmlinuz");
                if (!kernel)
                        return log_oom();

                if (access(kernel, F_OK) < 0)
                        return log_error_errno(errno, "Kernel not found at %s: %m", kernel);
        }

        STRV_FOREACH(i, arg_initrds)
                if (access(*i, F_OK) < 0)
                        return log_error_errno(errno, "Initrd not found at %s: %m", *i);

        r = find_qemu_binary(&qemu_binary);
        if (r == -EOPNOTSUPP)
                return log_error_errno(r, "Native architecture is not supported by qemu.");
        if (r < 0)
                return log_error_errno(r, "Failed to find QEMU binary: %m");

        if (asprintf(&mem, "%"PRIu64"M", arg_qemu_mem >> 20) < 0)
                return log_oom();

        cmdline = strv_new(
                qemu_binary,
                "-machine", machine,
                "-smp", arg_qemu_smp ?: "1",
                "-m", mem,
                "-object", "rng-random,filename=/dev/urandom,id=rng0",
                "-device", "virtio-rng-pci,rng=rng0,id=rng-device0"
        );
        if (!cmdline)
                return log_oom();

        switch (arg_qemu_net) {
        case QEMU_NET_NONE:
                r = strv_extend_strv(&cmdline, STRV_MAKE("-nic", "none"), /* filter_duplicates= */ false);
                break;
        case QEMU_NET_USER:
                r = strv_extend_strv(&cmdline, STRV_MAKE("-nic", "user,model=virtio-net-pci"), /* filter_duplicates= */ false);
                break;
        case QEMU_NET_TAP:
                r = strv_extend_strv(&cmdline, STRV_MAKE("-nic", "tap,script=no,model=virtio-net-pci"), /* filter_duplicates= */ false);
                break;
        default:
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid state for arg_qemu_net (%d), aborting.", arg_qemu_net);
        }
        if (r < 0)
                return log_oom();

        /* A shared memory backend might increase ram usage so only add one if actually necessary for virtiofsd. */
        if (arg_directory) {
                r = strv_extend(&cmdline, "-object");
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&cmdline, "memory-backend-memfd,id=mem,size=%s,share=on", mem);
                if (r < 0)
                        return log_oom();
        }

        bool use_vsock = arg_qemu_vsock > 0 && ARCHITECTURE_SUPPORTS_SMBIOS;
        if (arg_qemu_vsock < 0) {
                r = qemu_check_vsock_support();
                if (r < 0)
                        return log_error_errno(r, "Failed to check for VSock support: %m");

                use_vsock = r;
        }

        if (use_kvm && kvm_device_fd > 0) {
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

        r = strv_extend_strv(&cmdline, STRV_MAKE("-accel", accel), /* filter_duplicates= */ false);
        if (r < 0)
                return log_oom();

        _cleanup_close_ int child_vsock_fd = -EBADF;
        if (use_vsock) {
                int device_fd = vhost_device_fd;
                unsigned child_cid = (arg_vsock_cid < UINT_MAX) ? arg_vsock_cid : VMADDR_CID_ANY;

                if (device_fd < 0) {
                        child_vsock_fd = open("/dev/vhost-vsock", O_RDWR|O_CLOEXEC);
                        if (child_vsock_fd < 0)
                                return log_error_errno(errno, "Failed to open /dev/vhost-vsock as read/write: %m");

                        device_fd = child_vsock_fd;
                }

                r = vsock_fix_child_cid(device_fd, &child_cid, arg_machine);
                if (r < 0)
                        return log_error_errno(r, "Failed to fix CID for the guest vsock socket: %m");

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

        r = strv_extend_strv(&cmdline, STRV_MAKE("-cpu", "max"), /* filter_duplicates= */ false);
        if (r < 0)
                return log_oom();

        if (arg_qemu_gui) {
                r = strv_extend_strv(&cmdline, STRV_MAKE("-vga", "virtio"),  /* filter_duplicates= */ false);
                if (r < 0)
                        return log_oom();
        } else {
                r = strv_extend_strv(&cmdline, STRV_MAKE(
                        "-nographic",
                        "-nodefaults",
                        "-chardev", "stdio,mux=on,id=console,signal=off",
                        "-serial", "chardev:console",
                        "-mon", "console"
                ),  /* filter_duplicates= */ false);
                if (r < 0)
                        return log_oom();
        }

        if (ARCHITECTURE_SUPPORTS_SMBIOS)
                FOREACH_ARRAY(cred, arg_credentials.credentials, arg_credentials.n_credentials) {
                        _cleanup_free_ char *cred_data_b64 = NULL;
                        ssize_t n;

                        n = base64mem(cred->data, cred->size, &cred_data_b64);
                        if (n < 0)
                                return log_oom();

                        r = strv_extend(&cmdline, "-smbios");
                        if (r < 0)
                                return log_oom();

                        r = strv_extendf(&cmdline, "type=11,value=io.systemd.credential.binary:%s=%s", cred->id, cred_data_b64);
                        if (r < 0)
                                return log_oom();
                }

        r = strv_extend(&cmdline, "-drive");
        if (r < 0)
                return log_oom();

        r = strv_extendf(&cmdline, "if=pflash,format=raw,readonly=on,file=%s", ovmf_config->path);
        if (r < 0)
                return log_oom();

        _cleanup_(unlink_and_freep) char *ovmf_vars_to = NULL;
        if (ovmf_config->supports_sb) {
                const char *ovmf_vars_from = ovmf_config->vars;
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

                /* These aren't always available so don't raise an error if they fail */
                (void) copy_xattr(source_fd, NULL, target_fd, NULL, 0);
                (void) copy_access(source_fd, target_fd);
                (void) copy_times(source_fd, target_fd, 0);

                r = strv_extend_strv(&cmdline, STRV_MAKE(
                        "-global", "ICH9-LPC.disable_s3=1",
                        "-global", "driver=cfi.pflash01,property=secure,value=on",
                        "-drive"
                ),  /* filter_duplicates= */ false);
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&cmdline, "file=%s,if=pflash,format=raw", ovmf_vars_to);
                if (r < 0)
                        return log_oom();
        }

        if (kernel) {
                r = strv_extend_strv(&cmdline, STRV_MAKE("-kernel", kernel), /* filter_duplicates= */ false);
                if (r < 0)
                        return log_oom();
        }

        if (arg_image) {
                assert(!arg_directory);

                r = strv_extend(&cmdline, "-drive");
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&cmdline, "if=none,id=mkosi,file=%s,format=raw", arg_image);
                if (r < 0)
                        return log_oom();

                r = strv_extend_strv(&cmdline, STRV_MAKE(
                        "-device", "virtio-scsi-pci,id=scsi",
                        "-device", "scsi-hd,drive=mkosi,bootindex=1"
                ),  /* filter_duplicates= */ false);
                if (r < 0)
                        return log_oom();
        }

        if (arg_directory) {
                _cleanup_free_ char *sock_path = NULL, *sock_name = NULL;
                r = start_virtiofsd(bus, trans_scope, arg_directory, &sock_path, &sock_name);

                r = strv_extend(&cmdline, "-chardev");
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&cmdline, "socket,id=%1$s,path=%2$s/%1$s", sock_name, sock_path);
                if (r < 0)
                        return log_oom();

                r = strv_extend(&cmdline, "-device");
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&cmdline, "vhost-user-fs-pci,queue-size=1024,chardev=%s,tag=root", sock_name);
                if (r < 0)
                        return log_oom();

                r = strv_extend(&arg_kernel_cmdline_extra, "root=root rootfstype=virtiofs rw");
                if (r < 0)
                        return log_oom();
        }

        _cleanup_free_ char *swtpm = NULL;
        if (arg_vtpm != 0) {
                r = find_executable("swtpm", &swtpm);
                if (r < 0) {
                        /* log if the user asked for swtpm and we cannot find it */
                        if (arg_vtpm > 0)
                                return log_error_errno(r, "Failed to find swtpm binary: %m");
                        /* also log if we got an error other than ENOENT from find_executable */
                        else if (r != -ENOENT && arg_vtpm < 0)
                                return log_error_errno(r, "Error detecting swtpm: %m");
                }
        }

        _cleanup_free_ const char *vtpm_state_tempdir = NULL;
        if (swtpm) {
                r = start_vtpm(bus, trans_scope, swtpm, &vtpm_state_tempdir);
                if (r < 0) {
                        /* only bail if the user asked for a vtpm */
                        if (arg_vtpm > 0)
                                return log_error_errno(r, "Failed to start vtpm: %m");
                        log_debug_errno(r, "Failed to start vtpm, ignoring: %m");
                }

                r = strv_extend(&cmdline, "-chardev");
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&cmdline, "socket,id=chrtpm,path=%s/sock", vtpm_state_tempdir);
                if (r < 0)
                        return log_oom();

                r = strv_extend_strv(&cmdline, STRV_MAKE("-tpmdev", "emulator,id=tpm0,chardev=chrtpm"),
                                /* filter_duplicates= */ false);
                if (r < 0)
                        return log_oom();

                if (native_architecture() == ARCHITECTURE_X86_64)
                        r = strv_extend_strv(&cmdline, STRV_MAKE("-device", "tpm-tis,tpmdev=tpm0"), /* filter_duplicates= */ false);
                else if (IN_SET(native_architecture(), ARCHITECTURE_ARM64, ARCHITECTURE_ARM64_BE))
                        r = strv_extend_strv(&cmdline, STRV_MAKE("-device", "tpm-tis-device,tpmdev=tpm0"), /* filter_duplicates= */ false);
                if (r < 0)
                        return log_oom();
        }

        if (!strv_isempty(arg_kernel_cmdline_extra)) {
                _cleanup_free_ char *kcl = strv_join(arg_kernel_cmdline_extra, " ");
                if (!kcl)
                        return log_oom();

                if (kernel) {
                        r = strv_extend_strv(&cmdline, STRV_MAKE("-append", kcl), /* filter_duplicates= */ false);
                        if (r < 0)
                                return log_oom();
                } else {
                        if (ARCHITECTURE_SUPPORTS_SMBIOS) {
                                r = strv_extend(&cmdline, "-smbios");
                                if (r < 0)
                                        return log_oom();

                                r = strv_extendf(&cmdline, "type=11,value=io.systemd.stub.kernel-cmdline-extra=%s", kcl);
                                if (r < 0)
                                        return log_oom();
                        } else
                                log_warning("Cannot append extra args to kernel cmdline, native architecture doesn't support SMBIOS, ignoring");
                }
        }

        if (strv_isempty(arg_initrds) && kernel) {
                _cleanup_free_ char *initrd = NULL;
                r = find_initrd(kernel, &initrd);
                if (r < 0)
                        return log_error_errno(r, "Failed to find initrd: %m");

                if (initrd) {
                        r = strv_extend(&arg_initrds, initrd);
                        if (r < 0)
                                return log_oom();
                }
        }

        if (!strv_isempty(arg_initrds)) {
                r = strv_extend(&cmdline, "-initrd");
                if (r < 0)
                        return log_oom();

                r = strv_extend_strv(&cmdline, arg_initrds, /* filter_duplicates= */ false);
                if (r < 0)
                        return log_oom();
        }

        if (use_vsock) {
                notify_sock_fd = open_vsock();
                if (notify_sock_fd < 0)
                        return log_error_errno(notify_sock_fd, "Failed to open vsock: %m");

                r = cmdline_add_vsock(&cmdline, notify_sock_fd);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_error_errno(r, "Failed to call getsockname on vsock: %m");
        }

        _cleanup_(sd_event_source_unrefp) sd_event_source *notify_event_source = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        r = sd_event_new(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get default event source: %m");

        (void) sd_event_set_watchdog(event, true);

        pid_t child_pid;
        r = safe_fork_full(
                        qemu_binary,
                        NULL,
                        pass_fds, n_pass_fds,
                        FORK_CLOEXEC_OFF,
                        &child_pid);
        if (r < 0)
                return log_error_errno(r, "Failed to fork off %s: %m", qemu_binary);
        if (r == 0) {
                /* set TERM and LANG if they are missing */
                if (setenv("TERM", "vt220", 0) < 0)
                        return log_oom();

                if (setenv("LANG", "C.UTF-8", 0) < 0)
                        return log_oom();

                execve(qemu_binary, cmdline, environ);
                log_error_errno(errno, "Failed to execve %s: %m", qemu_binary);
                _exit(EXIT_FAILURE);
        }

        int exit_status = INT_MAX;
        if (use_vsock) {
                r = setup_notify_parent(event, notify_sock_fd, &exit_status, &notify_event_source);
                if (r < 0)
                        return log_error_errno(r, "Failed to setup event loop to handle vsock notify events: %m");
        }

        /* shutdown qemu when we are shutdown */
        (void) sd_event_add_signal(event, NULL, SIGINT, on_orderly_shutdown, PID_TO_PTR(child_pid));
        (void) sd_event_add_signal(event, NULL, SIGTERM, on_orderly_shutdown, PID_TO_PTR(child_pid));

        (void) sd_event_add_signal(event, NULL, SIGRTMIN+18, sigrtmin18_handler, NULL);

        /* Exit when the child exits */
        (void) sd_event_add_child(event, NULL, child_pid, WEXITED, on_child_exit, NULL);

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        if (use_vsock) {
                if (exit_status == INT_MAX) {
                        log_debug("Couldn't retrieve inner EXIT_STATUS from vsock");
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

        if (!arg_directory && !arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to determine path, please use -D or -i.");

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
        }

        return 0;
}

static int run(int argc, char *argv[]) {
        int r, kvm_device_fd = -EBADF, vhost_device_fd = -EBADF;
        _cleanup_strv_free_ char **names = NULL;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = determine_names();
        if (r < 0)
                return r;

        r = sd_listen_fds_with_names(true, &names);
        if (r < 0)
                return r;

        for (int i = 0; i < r; i++) {
                int fd = SD_LISTEN_FDS_START + i;
                if (streq(names[i], "kvm"))
                        kvm_device_fd = fd;
                else if (streq(names[i], "vhost-vsock"))
                        vhost_device_fd = fd;
                else {
                        log_notice("Couldn't recognise passed fd %d (%s), closing fd and ignoring...", fd, names[i]);
                        close(fd);
                }
        }

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD, SIGTERM, SIGINT, SIGRTMIN+18, -1) >= 0);

        return run_virtual_machine(kvm_device_fd, vhost_device_fd);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
