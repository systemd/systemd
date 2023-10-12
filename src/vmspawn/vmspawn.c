/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "alloc-util.h"
#include "architecture.h"
#include "build.h"
#include "copy.h"
#include "creds-util.h"
#include "escape.h"
#include "fileio.h"
#include "format-util.h"
#include "hexdecoct.h"
#include "log.h"
#include "main-func.h"
#include "pager.h"
#include "parse-util.h"
#include "path-util.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "process-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "machine-credential.h"
#include "vmspawn-settings.h"
#include "vmspawn-util.h"
#include "vmspawn.h"

static PagerFlags arg_pager_flags = 0;
static char *arg_image = NULL;
static char *arg_qemu_smp = NULL;
static uint64_t arg_qemu_mem = 2ULL * 1024ULL * 1024ULL * 1024ULL;
static int arg_qemu_kvm = -1;
static bool arg_qemu_gui = false;
static int arg_secboot = -1;
static MachineCredential *arg_credentials = NULL;
static size_t arg_n_credentials = 0;
static SettingsMask arg_settings_mask = 0;
static char **arg_parameters = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_qemu_smp, freep);
STATIC_DESTRUCTOR_REGISTER(arg_parameters, strv_freep);

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
               "  -i --image=PATH           Root file system disk image (or device node) for\n"
               "                            the virtual machine\n\n"
               "%3$sHost Configuration:%4$s\n"
               "     --qemu-smp=SMP         Configure guest's SMP settings\n"
               "     --qemu-mem=MEM         Configure guest's RAM size\n"
               "     --qemu-kvm=            Configure whether to use KVM or not\n"
               "     --qemu-gui             Start QEMU in graphical mode\n"
               "     --secboot=             Configure whether to search for firmware which supports secure boot\n\n"
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
                ARG_QEMU_GUI,
                ARG_SECBOOT,
                ARG_SET_CREDENTIAL,
                ARG_LOAD_CREDENTIAL,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                { "image",           required_argument, NULL, 'i'                 },
                { "qemu-smp",        required_argument, NULL, ARG_QEMU_SMP        },
                { "qemu-mem",        required_argument, NULL, ARG_QEMU_MEM        },
                { "qemu-kvm",        required_argument, NULL, ARG_QEMU_KVM        },
                { "qemu-gui",        no_argument,       NULL, ARG_QEMU_GUI        },
                { "secboot",         required_argument, NULL, ARG_SECBOOT         },
                { "set-credential",  required_argument, NULL, ARG_SET_CREDENTIAL  },
                { "load-credential", required_argument, NULL, ARG_LOAD_CREDENTIAL },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        optind = 0;
        while ((c = getopt_long(argc, argv, "+hi:", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case 'i':
                        r = parse_path_argument(optarg, false, &arg_image);
                        if (r < 0)
                                return r;

                        arg_settings_mask |= SETTING_DIRECTORY;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_QEMU_SMP:
                        arg_qemu_smp = strdup(optarg);
                        if (!arg_qemu_smp)
                                return log_oom();
                        break;

                case ARG_QEMU_MEM:
                        r = parse_size(optarg, 1024, &arg_qemu_mem);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse size from --qemu-mem=%s: %m", optarg);
                        break;

                case ARG_QEMU_KVM:
                        if (isempty(optarg))
                                arg_qemu_kvm = -1;
                        else {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                    return log_error_errno(r, "Failed to parse boolean from --qemu-kvm=%s: %m", optarg);
                                arg_qemu_kvm = r;
                        }
                        break;

                case ARG_QEMU_GUI:
                        arg_qemu_gui = true;
                        break;

                case ARG_SECBOOT:
                        if (isempty(optarg))
                                arg_secboot = -1;
                        else {
                                r = parse_boolean(optarg);
                                if (r < 0)
                                    return log_error_errno(r, "Failed to parse boolean from --secboot=%s: %m", optarg);
                                arg_secboot = r;
                        }
                        break;

                case ARG_SET_CREDENTIAL: {
                        r = machine_credential_set(&arg_credentials, &arg_n_credentials, optarg);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Failed to set credential from %s: %m", optarg);
                        arg_settings_mask |= SETTING_CREDENTIALS;
                        break;
                }

                case ARG_LOAD_CREDENTIAL: {
                        r = machine_credential_load(&arg_credentials, &arg_n_credentials, optarg);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Failed to load credential from %s: %m", optarg);

                        arg_settings_mask |= SETTING_CREDENTIALS;
                        break;
                }

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

        return 1;
}

static int run_virtual_machine(void) {
        _cleanup_(ovmf_config_freep) OvmfConfig *ovmf_config = NULL;
        _cleanup_strv_free_ char **cmdline = NULL;
        int r;

        const char *accel = "tcg";
        bool auto_conf_kvm = arg_qemu_kvm == -1 && qemu_check_kvm_support();
        if (arg_qemu_kvm == 1 || auto_conf_kvm)
                accel = "kvm";

        r = find_ovmf_config(arg_secboot, &ovmf_config);
        if (r < 0)
                return log_error_errno(r, "failed to find OVMF config: %m");

        if (!ovmf_config->supports_sb)
                log_warning("Couldn't find OVMF firmware blob with secure boot support, "
                            "falling back to OVMF firmware blobs without secure boot support.");
        const char *smm = ovmf_config->supports_sb ? "on" : "off";

        _cleanup_free_ char *machine = NULL;
#ifdef __aarch64__
        machine = strjoin("type=virt,accel=", accel);
#else
        machine = strjoin("type=q35,accel=", accel, ",smm=", smm);
#endif
        if (!machine)
                return log_oom();

        _cleanup_free_ char *qemu_binary = NULL;
        r = find_qemu_binary(&qemu_binary);
        if (r == -ESRCH)
                return log_error_errno(r, "Native architecture is not supported by qemu.");
        if (r < 0)
                return r;

        const char *smp = arg_qemu_smp ? arg_qemu_smp : "1";
        const char *mem = FORMAT_BYTES(arg_qemu_mem);
        cmdline = strv_new(
                qemu_binary,
                "-machine", machine,
                "-smp", smp,
                "-m", mem,
                "-object", "rng-random,filename=/dev/urandom,id=rng0",
                "-device", "virtio-rng-pci,rng=rng0,id=rng-device0",
                "-nic", "user,model=virtio-net-pci",
                "-cpu", "max"
        );

        if (arg_qemu_gui) {
                r = strv_extend_strv(&cmdline, STRV_MAKE("-vga", "virtio"), false);
                if (r < 0)
                        return log_oom();
        } else {
                r = strv_extend_strv(&cmdline, STRV_MAKE(
                        "-nographic",
                        "-nodefaults",
                        "-chardev", "stdio,mux=on,id=console,signal=off",
                        "-serial", "chardev:console",
                        "-mon", "console"
                ), false);
                if (r < 0)
                        return log_oom();
        }

#ifdef ARCHITECTURE_SUPPORTS_SMBIOS
        ssize_t n;
        FOREACH_ARRAY(cred, arg_credentials, arg_n_credentials) {
                _cleanup_free_ char *cred_data_b64 = NULL;

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
#endif

        r = strv_extend(&cmdline, "-drive");
        if (r < 0)
                return log_oom();

        r = strv_extendf(&cmdline, "if=pflash,format=raw,readonly=on,file=%s", ovmf_config->path);
        if (r < 0)
                return log_oom();

        if (ovmf_config->supports_sb) {
                const char *ovmf_vars_from = ovmf_config->vars;
                _cleanup_free_ char *ovmf_vars_to = NULL;
                r = tempfn_random_child(NULL, "vmspawn-", &ovmf_vars_to);
                if (r < 0)
                        return r;

                _cleanup_close_ int source_fd = -EBADF, target_fd = -EBADF;
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
                ), false);
                if (r < 0)
                        return log_oom();

                r = strv_extendf(&cmdline, "file=%s,if=pflash,format=raw", ovmf_vars_to);
                if (r < 0)
                        return log_oom();
        }

        r = strv_extend(&cmdline, "-drive");
        if (r < 0)
                return log_oom();

        r = strv_extendf(&cmdline, "if=none,id=mkosi,file=%s,format=raw", arg_image);
        if (r < 0)
                return log_oom();

        r = strv_extend_strv(&cmdline, STRV_MAKE(
                "-device", "virtio-scsi-pci,id=scsi",
                "-device", "scsi-hd,drive=mkosi,bootindex=1"
        ), false);
        if (r < 0)
                return log_oom();

        r = strv_extend_strv(&cmdline, arg_parameters, false);
        if (r < 0)
                return log_oom();

        pid_t child_pid, pid;
        pid = safe_fork(qemu_binary, 0, &child_pid);
        if (pid == 0) {
                /* set TERM and LANG if they are missing */
                r = setenv("TERM", "vt220", 0);
                if (r < 0)
                        return log_oom();

                r = setenv("LANG", "C.UTF-8", 0);
                if (r < 0)
                        return log_oom();

                execve(qemu_binary, cmdline, environ);
                log_error_errno(errno, "failed to execve %s: %m", qemu_binary);
                _exit(r);
        } else {
                return wait_for_terminate_and_check(qemu_binary, child_pid, WAIT_LOG);
        }
}

static int run(int argc, char *argv[]) {
        int r, ret = EXIT_SUCCESS;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (!arg_image) {
                log_error("missing required argument -i/--image, quitting");
                goto finish;
        }

        r = run_virtual_machine();
finish:
        machine_credential_free_all(arg_credentials, arg_n_credentials);

        if (r < 0)
                return r;

        return ret;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
