/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "architecture.h"
#include "build.h"
#include "copy.h"
#include "creds-util.h"
#include "escape.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "log.h"
#include "main-func.h"
#include "pager.h"
#include "path-util.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "process-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "vmspawn-creds.h"
#include "vmspawn-settings.h"
#include "vmspawn-util.h"
#include "vmspawn.h"

static PagerFlags arg_pager_flags = 0;
static ConfigFeature arg_qemu_kvm = CONFIG_FEATURE_AUTO;
static QemuFirmware arg_qemu_firmware = QEMU_FIRMWARE_UEFI;
static char* arg_qemu_smp = NULL;
static char* arg_qemu_mem = NULL;
static char* arg_image = NULL;
static bool arg_qemu_gui = false;
static bool arg_qemu_cdrom = false;
static Credential *arg_credentials = NULL;
static size_t arg_n_credentials = 0;
static SettingsMask arg_settings_mask = 0;

STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_qemu_smp, freep);
STATIC_DESTRUCTOR_REGISTER(arg_qemu_mem, freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        pager_open(arg_pager_flags);

        r = terminal_urlify_man("systemd-vmspawn", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...]\n\n"
               "%5$sSpawn a command or OS in a virtual machine.%6$s\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Print version string\n"
               "     --no-pager             Do not pipe output into a pager\n\n"
               "%3$sImage:%4$s\n"
               "  -i --image=PATH           Root file system disk image (or device node) for\n"
               "                            the virtual machine\n"
               "%3$sHost Configuration:%4$s\n"
               "     --qemu-smp=SMP         Configure guest's SMP settings\n"
               "     --qemu-mem=MEM         Configure guest's RAM size\n"
               "     --qemu-kvm=auto|enabled|disabled\n"
               "                            Configure whether to use KVM or not\n"
               "     --qemu-cdrom           Attach the image as a CD-ROM to the virtual machine\n"
               "     --qemu-firmware=direct|uefi|bios\n"
               "                            Set qemu firmware to use\n"
               "     --qemu-gui             Start QEMU in graphical mode\n"
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
                ARG_QEMU_CDROM,
                ARG_QEMU_FIRMWARE,
                ARG_QEMU_GUI,
                ARG_SET_CREDENTIAL,
                ARG_LOAD_CREDENTIAL,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                { "image",           required_argument, NULL, 'i'                 },
                { "qemu-smp",        optional_argument, NULL, ARG_QEMU_SMP        },
                { "qemu-mem",        optional_argument, NULL, ARG_QEMU_MEM        },
                { "qemu-kvm",        optional_argument, NULL, ARG_QEMU_KVM        },
                { "qemu-cdrom",      no_argument,       NULL, ARG_QEMU_CDROM      },
                { "qemu-firmware",   optional_argument, NULL, ARG_QEMU_FIRMWARE   },
                { "qemu-gui",        no_argument,       NULL, ARG_QEMU_GUI        },
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
                                log_oom();
                        break;

                case ARG_QEMU_MEM:
                        arg_qemu_mem = strdup(optarg);
                        if (!arg_qemu_mem)
                                log_oom();
                        break;

                case ARG_QEMU_KVM:
                        r = parse_config_feature(optarg, &arg_qemu_kvm);
                        if (r < 0)
                                return r;
                        break;

                case ARG_QEMU_CDROM:
                        arg_qemu_cdrom = true;
                        break;

                case ARG_QEMU_FIRMWARE:
                        r = parse_qemu_firmware(optarg, &arg_qemu_firmware);
                        if (r < 0)
                                return r;
                        break;

                case ARG_QEMU_GUI:
                        arg_qemu_gui = true;
                        break;

                case ARG_SET_CREDENTIAL: {
                        _cleanup_free_ char *word = NULL, *data = NULL;
                        const char *p = optarg;
                        Credential *a;
                        ssize_t l;

                        r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --set-credential= parameter: %m");
                        if (r == 0 || !p)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing value for --set-credential=: %s", optarg);

                        if (!credential_name_valid(word))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Credential name is not valid: %s", word);

                        for (size_t i = 0; i < arg_n_credentials; i++)
                                if (streq(arg_credentials[i].id, word))
                                        return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Duplicate credential '%s', refusing.", word);

                        l = cunescape(p, UNESCAPE_ACCEPT_NUL, &data);
                        if (l < 0)
                                return log_error_errno(l, "Failed to unescape credential data: %s", p);

                        a = reallocarray(arg_credentials, arg_n_credentials + 1, sizeof(Credential));
                        if (!a)
                                return log_oom();

                        a[arg_n_credentials++] = (Credential) {
                                .id = TAKE_PTR(word),
                                .data = TAKE_PTR(data),
                                .size = l,
                        };

                        arg_credentials = a;

                        arg_settings_mask |= SETTING_CREDENTIALS;
                        break;
                }

                case ARG_LOAD_CREDENTIAL: {
                        ReadFullFileFlags flags = READ_FULL_FILE_SECURE;
                        _cleanup_(erase_and_freep) char *data = NULL;
                        _cleanup_free_ char *word = NULL, *j = NULL;
                        const char *p = optarg;
                        Credential *a;
                        size_t size, i;

                        r = extract_first_word(&p, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --load-credential= parameter: %m");
                        if (r == 0 || !p)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Missing value for --load-credential=: %s", optarg);

                        if (!credential_name_valid(word))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Credential name is not valid: %s", word);

                        for (i = 0; i < arg_n_credentials; i++)
                                if (streq(arg_credentials[i].id, word))
                                        return log_error_errno(SYNTHETIC_ERRNO(EEXIST), "Duplicate credential '%s', refusing.", word);

                        if (path_is_absolute(p))
                                flags |= READ_FULL_FILE_CONNECT_SOCKET;
                        else {
                                const char *e;

                                r = get_credentials_dir(&e);
                                if (r < 0)
                                        return log_error_errno(r, "Credential not available (no credentials passed at all): %s", word);

                                j = path_join(e, p);
                                if (!j)
                                        return log_oom();
                        }

                        r = read_full_file_full(AT_FDCWD, j ?: p, UINT64_MAX, SIZE_MAX,
                                                flags,
                                                NULL,
                                                &data, &size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read credential '%s': %m", j ?: p);

                        a = reallocarray(arg_credentials, arg_n_credentials + 1, sizeof(Credential));
                        if (!a)
                                return log_oom();

                        a[arg_n_credentials++] = (Credential) {
                                .id = TAKE_PTR(word),
                                .data = TAKE_PTR(data),
                                .size = size,
                        };

                        arg_credentials = a;

                        arg_settings_mask |= SETTING_CREDENTIALS;
                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        return 1;
}

static int run_virtual_machine(void) {
        int r;
        const char* accel = "tcg";
        _cleanup_strv_free_ char **cmdline = NULL;

        bool auto_conf_kvm = arg_qemu_kvm == CONFIG_FEATURE_AUTO && qemu_check_kvm_support(true);
        if (arg_qemu_kvm == CONFIG_FEATURE_ENABLED || auto_conf_kvm)
                accel = "kvm";

        const char* firmware_path = NULL;
        r = find_ovmf_firmware(&firmware_path);
        if (r < 0)
                return r;
        bool fw_supports_sb = r == 0;
        const char* smm = arg_qemu_firmware == QEMU_FIRMWARE_UEFI && fw_supports_sb ? "on" : "off";

        _cleanup_free_ char* machine = NULL;
#ifdef __aarch64__
        r = asprintf(&machine, "type=virt,accel=%s", accel);
#else
        r = asprintf(&machine, "type=q35,accel=%s,smm=%s", accel, smm);
#endif
        if (r < 0)
                log_oom();

        _cleanup_free_ char* qemu_binary = NULL;
        r = find_qemu_binary(&qemu_binary);
        if (r < 0)
                return r;

        const char *smp = arg_qemu_smp ? arg_qemu_smp : "1",
                   *mem = arg_qemu_mem ? arg_qemu_mem : "2G";

        cmdline = strv_new(
                qemu_binary,
                "-machine", machine,
                "-smp", smp,
                "-m", mem,
                "-object", "rng-random,filename=/dev/urandom,id=rng0",
                "-device", "virtio-rng-pci,rng=rng0,id=rng-device0",
                "-nic", "user,model=virtio-net-pci"
        );

        // add vsock support here

        strv_extend(&cmdline, "-cpu");
        strv_extend(&cmdline, "max");

        if (arg_qemu_gui) {
                strv_extend(&cmdline, "-vga");
                strv_extend(&cmdline, "virtio");
        } else {
                FOREACH_STRING(s,
                                "-nographic",
                                "-nodefaults",
                                "-chardev", "stdio,mux=on,id=console,signal=off",
                                "-serial", "chardev:console",
                                "-mon", "console")
                        strv_extend(&cmdline, s);
        }

        ssize_t n;
        for (size_t i = 0; i < arg_n_credentials; i++) {
                _cleanup_free_ char* cred_data_b64 = NULL;
                Credential* cred = &arg_credentials[i];

                n = base64mem(cred->data, cred->size, &cred_data_b64);
                if (n < 0)
                        return log_oom();

                strv_extend(&cmdline, "-smbios");
                strv_extendf(&cmdline, "type=11,value=io.systemd.credential.binary:%s=%s", cred->id, cred_data_b64);
        }

        if (arg_qemu_firmware == QEMU_FIRMWARE_UEFI) {
                strv_extend(&cmdline, "-drive");
                strv_extendf(&cmdline, "if=pflash,format=raw,readonly=on,file=%s", firmware_path);
        }

        if (arg_qemu_firmware == QEMU_FIRMWARE_UEFI && fw_supports_sb) {
                const char* ovmf_vars_from = NULL;
                r = find_ovmf_vars(&ovmf_vars_from);
                if (r < 0)
                        return r;

                _cleanup_free_ char* ovmf_vars_to = NULL;
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

                FOREACH_STRING(s,
                                "-global", "ICH9-LPC.disable_s3=1",
                                "-global", "driver=cfi.pflash01,property=secure,value=on",
                                "-drive")
                        strv_extend(&cmdline, s);
                strv_extendf(&cmdline, "file=%s,if=pflash,format=raw", ovmf_vars_to);
        }

        strv_extend(&cmdline, "-drive");
        strv_extendf(&cmdline, "if=none,id=mkosi,file=%s,format=raw", arg_image);
        strv_extend(&cmdline, "-device");
        strv_extend(&cmdline, "virtio-scsi-pci,id=scsi");
        strv_extend(&cmdline, "-device");
        strv_extendf(&cmdline, "scsi-%s,drive=mkosi,bootindex=1", arg_qemu_cdrom ? "cd" : "hd");

        int child_status;
        pid_t child_pid, pid;
        pid = safe_fork(qemu_binary, 0, &child_pid);
        if (pid == 0) {
                /* set TERM and LANG if they are missing */
                r = setenv("TERM", "vt220", 0);
                if (r < 0)
                        log_oom();

                r = setenv("LANG", "C.UTF-8", 0);
                if (r < 0)
                        log_oom();

                r = execve(qemu_binary, cmdline, environ);
                log_error_errno(r, "failed to execve %s: %m", qemu_binary);
                _exit(r);
        } else {
                wait(&child_status);
                int exit_status = WEXITSTATUS(child_status);
                if (exit_status != 0) {
                        log_error("qemu process exited with code %d", exit_status);
                        return exit_status;
                }
        }

        return 0;
}

static int run(int argc, char *argv[]) {
        int r, ret = EXIT_SUCCESS;

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (!arg_image) {
                log_error("missing required argument -i/--image, quitting");
                goto finish;
        }

        r = run_virtual_machine();
        if (r != 0)
                goto finish;
finish:
        credential_free_all(arg_credentials, arg_n_credentials);

        if (r < 0)
                return r;

        return ret;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
