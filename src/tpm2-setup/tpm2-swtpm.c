/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/vtpm_proxy.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "chase.h"
#include "dlopen-note.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "find-esp.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "hmac.h"
#include "initrd-util.h"
#include "iovec-util.h"
#include "log.h"
#include "main-func.h"
#include "path-lookup.h"
#include "path-util.h"
#include "rm-rf.h"
#include "sha256.h"
#include "string-util.h"
#include "strv.h"
#include "swtpm-util.h"
#include "time-util.h"
#include "verbs.h"

COMMAND(
        "systemd-tpm2-swtpm\0",
        "Provide a fallback software TPM.",
        .man_page = "systemd-tpm2-swtpm.service(8)",
        .option_namespace = "common",
);

#define BOOT_SECRET_SIZE 32U

/* The TPM is expected at /dev/tpm0 and /dev/tpmrm0, e.g., by tpm2.target. After the initrd transition the
 * number of the device from the initrd might not be released yet, hence retry for a while then. */
#define VTPM_RETRY_TIMEOUT_USEC (10 * USEC_PER_SEC)
#define VTPM_RETRY_INTERVAL_USEC (100 * USEC_PER_MSEC)

static int load_boot_secret(struct iovec *ret) {
        _cleanup_(iovec_done_erase) struct iovec buf = {};
        int r;

        assert(ret);

        const char *bs = in_initrd() ? "/.extra/boot-secret" : "/run/systemd/stub/boot-secret";
        r = read_full_file_full(
                        AT_FDCWD,
                        bs,
                        UINT64_MAX,
                        BOOT_SECRET_SIZE,
                        READ_FULL_FILE_SECURE|READ_FULL_FILE_VERIFY_REGULAR,
                        /* bind_name= */ NULL,
                        (char**) &buf.iov_base,
                        &buf.iov_len);
        if (r == -ENOENT) {
                log_warning_errno(r, "Boot secret (%s) not found, not encrypting software TPM state!", bs);
                *ret = (struct iovec) {};
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read '%s': %m", bs);

        if (buf.iov_len < BOOT_SECRET_SIZE)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Boot secret too short, refusing.");

        *ret = TAKE_STRUCT(buf);
        return 1;
}

static int prepare_secret(const char *runtime_dir, char **ret) {
        int r;

        assert(runtime_dir);
        assert(ret);

        _cleanup_(iovec_done_erase) struct iovec boot_secret = {};
        r = load_boot_secret(&boot_secret);
        if (r < 0)
                return r;
        if (r == 0) {
                *ret = NULL;
                return 0;
        }

        /* Derive a suitable swtpm specific secret */
        static const char tag[] = "systemd swtpm tag v1";
        uint8_t secret[SHA256_DIGEST_SIZE];
        CLEANUP_ERASE(secret);
        hmac_sha256(boot_secret.iov_base,
                    boot_secret.iov_len,
                    tag,
                    strlen(tag),
                    secret);

        _cleanup_free_ char *p = path_join(runtime_dir, "secret");
        if (!p)
                return log_oom();

        assert_cc(sizeof(secret) >= 16); /* swtpm only wants a 16 byte key */
        _cleanup_(erase_and_freep) char *h = hexmem(secret, 16);
        if (!h)
                return log_oom();

        r = write_data_file_atomic_at(XAT_FDROOT, p, &IOVEC_MAKE_STRING(h), WRITE_DATA_FILE_MODE_0400);
        if (r < 0)
                return log_error_errno(r, "Failed to write secret file: %m");

        *ret = TAKE_PTR(p);
        return 1;
}

static int setup_swtpm(const char *state_dir, int state_fd, const char *secret) {
        int r;

        assert(state_dir);
        assert(state_fd >= 0);

        /* Sets up the state directory via swtpm_setup */

        if (in_initrd()) {
                /* In the initrd remove previous transient state */
                r = RET_NERRNO(unlinkat(state_fd, "tpm2-00.volatilestate", /* flags= */ 0));
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to remove 'tpm2-00.volatilestate': %m");
        }

        /* manufacture_swtpm() writes its marker only after swtpm_setup has fully created the TPM state.
         * If the marker file is missing, the existing state is incomplete and recreation is needed. */
        r = RET_NERRNO(faccessat(state_fd, SWTPM_MANUFACTURED_MARKER, F_OK, AT_SYMLINK_NOFOLLOW));
        if (r >= 0) {
                log_debug("TPM state directory holds a fully manufactured TPM, not manufacturing a TPM.");
                return 0;
        }
        if (r != -ENOENT)
                return log_error_errno(r, "Failed to check for TPM manufacture marker: %m");

        if (!in_initrd())
                return log_error_errno(SYNTHETIC_ERRNO(ESTALE), "swtpm TPM state directory has not been initialized in the initrd, refusing.");

        /* Cleanup incomplete state before recreating. */
        _cleanup_close_ int wipe_fd = fd_reopen(state_fd, O_RDONLY|O_DIRECTORY);
        if (wipe_fd < 0)
                return log_error_errno(wipe_fd, "Failed to reopen swtpm state directory: %m");
        r = rm_rf_children(TAKE_FD(wipe_fd), REMOVE_PHYSICAL, /* root_dev= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to clear incomplete swtpm state directory: %m");

        log_debug("TPM state directory holds no fully manufactured TPM, manufacturing a TPM.");

        return manufacture_swtpm(state_dir, secret);
}

static int create_vtpm_proxy(int *ret_fd, uint32_t *ret_tpm_num) {
        struct vtpm_proxy_new_dev dev = {
                .flags = VTPM_PROXY_FLAG_TPM2,
        };

        assert(ret_fd);
        assert(ret_tpm_num);

        _cleanup_close_ int vtpmx_fd = open("/dev/vtpmx", O_RDWR|O_CLOEXEC);
        if (vtpmx_fd < 0)
                return log_error_errno(errno, "Failed to open /dev/vtpmx: %m");

        if (ioctl(vtpmx_fd, VTPM_PROXY_IOC_NEW_DEV, &dev) < 0)
                return log_error_errno(errno, "Failed to create vTPM proxy device: %m");

        *ret_fd = (int) dev.fd;
        *ret_tpm_num = dev.tpm_num;
        return 0;
}

static int acquire_vtpm_proxy(int *ret_fd) {
        usec_t deadline = usec_add(now(CLOCK_MONOTONIC), VTPM_RETRY_TIMEOUT_USEC);
        bool waiting = false;
        int r;

        assert(ret_fd);

        for (;;) {
                _cleanup_close_ int fd = -EBADF;
                uint32_t tpm_num;

                r = create_vtpm_proxy(&fd, &tpm_num);
                if (r < 0)
                        return r;

                /* Take the device if it got number 0, or if another TPM has that number anyway. */
                if (tpm_num == 0 || access("/sys/class/tpm/tpm0", F_OK) >= 0) {
                        log_debug("Created TPM device /dev/tpm%" PRIu32 ".", tpm_num);
                        *ret_fd = TAKE_FD(fd);
                        return 0;
                }

                if (now(CLOCK_MONOTONIC) >= deadline) {
                        log_warning("TPM device number 0 was not released in time, using /dev/tpm%" PRIu32 " instead.",
                                    tpm_num);
                        *ret_fd = TAKE_FD(fd);
                        return 0;
                }

                if (!waiting) {
                        log_notice("TPM device number 0 is still taken, waiting for it to be released.");
                        waiting = true;
                }

                /* Nothing answers the commands of this device yet, so it never gets registered and closing it
                 * releases its number again right away. */
                fd = safe_close(fd);
                (void) usleep_safe(VTPM_RETRY_INTERVAL_USEC);
        }
}

static int run(int argc, char *argv[]) {
        int r;

        LIBBLKID_NOTE(recommended);

        log_setup();

        r = common_parse_argv_full(argc, argv, /* min_args= */ 0, /* max_args= */ 0, /* ret_args= */ NULL);
        if (r <= 0)
                return r;

        _cleanup_free_ char *runtime_dir = NULL;
        r = runtime_directory(RUNTIME_SCOPE_SYSTEM, "systemd/swtpm", &runtime_dir);
        if (r < 0)
                return log_error_errno(r, "Unable to determine runtime directory: %m");

        _cleanup_free_ char *swtpm = NULL;
        r = find_executable("swtpm", &swtpm);
        if (r < 0)
                return log_error_errno(r, "Failed to find 'swtpm' binary: %m");

        _cleanup_free_ char *state_dir = NULL;
        _cleanup_close_ int state_fd = -EBADF;
        if (in_initrd()) {
                /* The early ESP support uses only a single mount point, we do not need to search for it. */
                r = chase("/loader/swtpm",
                          "/sysefi",
                          CHASE_PREFIX_ROOT|CHASE_TRIGGER_AUTOFS|CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                          &state_dir,
                          &state_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to open swtpm state directory in ESP: %m");
        } else {
                _cleanup_free_ char *esp_path = NULL;
                _cleanup_close_ int esp_fd = -EBADF;
                r = find_esp_and_warn(
                                /* root= */ NULL,
                                /* path= */ NULL,
                                /* unprivileged_mode= */ false,
                                &esp_path,
                                &esp_fd);
                if (r == -ENOKEY) /* This one find_esp_and_warn() doesn't actually log about. */
                        return log_error_errno(r, "No ESP discovered.");
                if (r < 0)
                        return r;

                _cleanup_free_ char *unprefixed_state_dir = NULL;
                r = chaseat(esp_fd,
                            esp_fd,
                            "/loader/swtpm",
                            CHASE_TRIGGER_AUTOFS|CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                            &unprefixed_state_dir,
                            &state_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to open swtpm state directory in ESP: %m");

                state_dir = path_join(esp_path, unprefixed_state_dir);
                if (!state_dir)
                        return log_oom();
        }

        _cleanup_(unlink_and_freep) char *secret = NULL;
        r = prepare_secret(runtime_dir, &secret);
        if (r < 0)
                return r;

        r = setup_swtpm(state_dir, state_fd, secret);
        if (r < 0)
                return r;

        /* Create the vTPM proxy device ourselves instead of using swtpm's --vtpm-proxy, so that we know its
         * number. */
        _cleanup_close_ int vtpm_fd = -EBADF;
        r = acquire_vtpm_proxy(&vtpm_fd);
        if (r < 0)
                return r;

        r = fd_cloexec(vtpm_fd, false);
        if (r < 0)
                return log_error_errno(r, "Failed to pass vTPM proxy device to swtpm: %m");

        _cleanup_strv_free_ char **args =
                strv_new(swtpm,
                         "chardev",
                         "--tpm2",
                         /* Implied by --vtpm-proxy, as the vTPM proxy driver sends TPM2_SetLocality(). */
                         "--locality=allow-set-locality",
                         /* not-need-init is implied by --vtpm-proxy too. Make sure that in the initrd swtpm
                          * never sends TPM2_Shutdown() for us, we want to be able to stop the daemon after all
                          * temporarily during the initrd→host transition. */
                         in_initrd() ? "--flags=not-need-init,startup-clear,disable-auto-shutdown" :
                                       "--flags=not-need-init,startup-clear");
        if (!args)
                return log_oom();

        if (strv_extendf(&args, "--fd=%i", vtpm_fd) < 0)
                return log_oom();

        if (strv_extendf(&args, "--ctrl=type=unixio,path=%s/socket", runtime_dir) < 0)
                return log_oom();

        if (secret && strv_extendf(&args, "--key=file=%s,format=hex,mode=aes-cbc,remove=true", secret) < 0)
                return log_oom();

        if (strv_extendf(&args, "--tpmstate=dir=%s,mode=0600", state_dir) < 0)
                return log_oom();

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *cmd = quote_command_line(args, SHELL_ESCAPE_EMPTY);

                log_debug("Chain-loading: %s", strnull(cmd));
        }

        /* Ideally swtpm could send this itself, but for now let's accept it like this. */
        // FIXME: remove this once swtpm 0.11 is released and hit all relevant distros. Then bump version
        // requirements.
        (void) sd_notify(/* unset_environment= */ true, "READY=1");

        /* NB: if the execve() succeeds it's swtpm's job to actually unlink the secret file */
        execv(swtpm, args);
        return log_error_errno(errno, "Failed to chainload swtpm: %m");
}

DEFINE_MAIN_FUNCTION(run);
