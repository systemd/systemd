/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/vtpm_proxy.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "chase.h"
#include "devnum-util.h"
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
#include "verbs.h"

COMMAND(
        "systemd-tpm2-swtpm\0",
        "Provide a fallback software TPM.",
        .man_page = "systemd-tpm2-swtpm.service(8)",
        .option_namespace = "common",
);

#define BOOT_SECRET_SIZE 32U

/* The name of the vTPM proxy device fd in the service's fdstore */
#define VTPM_PROXY_FDNAME "vtpm-proxy"

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

static int take_vtpm_proxy_from_fdstore(void) {
        /* Returns the vTPM proxy device fd from the fdstore, or -ENOENT if there is none.
         *
         * We allocate the vTPM proxy device ourselves (rather than letting swtpm do it), and keep its fd in
         * our fdstore. This way the kernel TPM device stays around while swtpm is stopped, i.e. across
         * service restarts and in particular across the initrd→host transition: the device is never
         * released and reallocated, hence it keeps its device number (i.e. stays /dev/tpm0), and kernel
         * users (such as trusted.ko) that took a reference to the TPM chip keep a working TPM. */

        _cleanup_strv_free_ char **names = NULL;
        int n = sd_listen_fds_with_names(/* unset_environment= */ true, &names);
        if (n < 0)
                return log_error_errno(n, "Failed to determine passed file descriptors: %m");

        _cleanup_close_ int fd = -EBADF;
        for (int i = 0; i < n; i++) {
                _cleanup_close_ int k = SD_LISTEN_FDS_START + i;

                if (!streq(names[i], VTPM_PROXY_FDNAME)) {
                        log_warning("Passed file descriptor with unexpected name '%s', closing.", names[i]);
                        continue;
                }

                if (fd >= 0) {
                        log_warning("Passed more than one vTPM proxy device file descriptor, closing the extra one.");
                        continue;
                }

                fd = TAKE_FD(k);
        }

        if (fd < 0)
                return -ENOENT;

        log_info("Reusing vTPM proxy device from file descriptor store.");
        return TAKE_FD(fd);
}

static int allocate_vtpm_proxy(const char *runtime_dir) {
        int r;

        assert(runtime_dir);

        _cleanup_close_ int vtpmx_fd = xopenat(AT_FDCWD, "/dev/vtpmx", O_RDWR);
        if (vtpmx_fd < 0)
                return log_error_errno(vtpmx_fd, "Failed to open /dev/vtpmx: %m");

        struct vtpm_proxy_new_dev d = {
                .flags = VTPM_PROXY_FLAG_TPM2,
        };
        if (ioctl(vtpmx_fd, VTPM_PROXY_IOC_NEW_DEV, &d) < 0)
                return log_error_errno(errno, "Failed to allocate vTPM proxy device: %m");

        _cleanup_close_ int fd = fd_move_above_stdio((int) d.fd);

        /* We are just a polyfill for systems lacking a TPM. If the device we got is not tpm0, then someone
         * else already provides a TPM, and we should not have been started in the first place. Closing the
         * fd releases the device again. */
        if (d.tpm_num != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY),
                                       "Allocated vTPM proxy device is /dev/tpm%" PRIu32 " rather than /dev/tpm0, another TPM is already present, refusing.",
                                       d.tpm_num);

        log_info("Allocated vTPM proxy device /dev/tpm0 (%" PRIu32 ":%" PRIu32 ").", d.major, d.minor);

        /* The device will survive us once it is in the fdstore, hence tell systemd-tpm2-generator that this
         * TPM is ours, so that after the initrd→host transition it pulls us in again, even though a TPM
         * exists. Do this before pushing the fd into the fdstore, so that the device is never pinned
         * without being recognizable as ours. */
        _cleanup_free_ char *p = path_join(runtime_dir, SWTPM_DEVNO_FILENAME);
        if (!p)
                return log_oom();

        r = write_string_filef(
                        p,
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC,
                        DEVNUM_FORMAT_STR,
                        DEVNUM_FORMAT_VAL(makedev(d.major, d.minor)));
        if (r < 0)
                return log_error_errno(r, "Failed to write '%s': %m", p);

        /* PID 1 only watches for EPOLLHUP/EPOLLERR on fdstore entries. The vTPM proxy device signals
         * EPOLLHUP if the kernel failed to register the TPM chip (e.g. because swtpm died during
         * initialization), in which case the fd is useless and shall be dropped from the fdstore, so that
         * we allocate a new device on the next start. */
        r = sd_pid_notify_with_fds(
                        /* pid= */ 0,
                        /* unset_environment= */ false,
                        "FDSTORE=1\n"
                        "FDNAME=" VTPM_PROXY_FDNAME,
                        &fd,
                        1);
        if (r <= 0) {
                if (r < 0)
                        log_warning_errno(r, "Failed to push vTPM proxy device to file descriptor store, ignoring: %m");
                else
                        log_debug("Not running as a service, not pushing vTPM proxy device to file descriptor store.");

                /* The device goes away with us, hence don't claim it as ours beyond our lifetime. */
                if (unlink(p) < 0 && errno != ENOENT)
                        log_debug_errno(errno, "Failed to remove '%s', ignoring: %m", p);
        }

        return TAKE_FD(fd);
}

static int run(int argc, char *argv[]) {
        int r;

        LIBBLKID_NOTE(recommended);

        log_setup();

        r = common_parse_argv_full(argc, argv, /* min_args= */ 0, /* max_args= */ 0, /* ret_args= */ NULL);
        if (r <= 0)
                return r;

        /* Do this first, so that the passed fds are marked O_CLOEXEC before we fork off swtpm_setup */
        _cleanup_close_ int vtpm_fd = take_vtpm_proxy_from_fdstore();
        if (vtpm_fd < 0 && vtpm_fd != -ENOENT)
                return vtpm_fd;

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

        /* Allocate a new device only now, right before invoking swtpm, since the kernel starts talking to
         * the TPM as soon as the device exists. */
        if (vtpm_fd < 0) {
                vtpm_fd = allocate_vtpm_proxy(runtime_dir);
                if (vtpm_fd < 0)
                        return vtpm_fd;
        }

        /* swtpm shall inherit the fd */
        r = fd_cloexec(vtpm_fd, /* cloexec= */ false);
        if (r < 0)
                return log_error_errno(r, "Failed to disable O_CLOEXEC on vTPM proxy device fd: %m");

        /* Since we pass the vTPM proxy device fd in instead of using --vtpm-proxy, we need to explicitly
         * turn on what --vtpm-proxy implies: no CMD_INIT needed, and the kernel's SetLocality commands are
         * accepted. */
        _cleanup_strv_free_ char **args =
                strv_new(swtpm,
                         "chardev",
                         "--tpm2",
                         "--locality=allow-set-locality",
                         /* Make sure that in the initrd swtpm never sends TPM2_Shutdown() for us, we want to
                          * be able to stop the daemon after all temporarily during the initrd→host
                          * transition. */
                         in_initrd() ? "--flags=not-need-init,startup-clear,disable-auto-shutdown" : "--flags=not-need-init,startup-clear");
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
