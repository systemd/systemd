/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "chase.h"
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
#include "sha256.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "swtpm-util.h"

#define BOOT_SECRET_SIZE 32U

static int load_boot_secret(struct iovec *ret) {
        _cleanup_(iovec_done_erase) struct iovec buf = {};
        int r;

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

        r = dir_is_empty_at(state_fd, /* path= */ NULL, /* ignore_hidden_or_backup= */ false);
        if (r < 0)
                return log_error_errno(r, "Failed to check if TPM state directory is empty: %m");
        if (r == 0) {
                log_debug("TPM state directory is already populated, not manufacturing a TPM.");
                return 0;
        }

        if (!in_initrd())
                return log_error_errno(SYNTHETIC_ERRNO(ESTALE), "swtpm TPM state directory has not been initialized in the initrd, refusing.");

        log_debug("TPM state directory is unpopulated, manufacturing a TPM.");

        return manufacture_swtpm(state_dir, secret);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        _cleanup_free_ char *runtime_dir = NULL;
        r = runtime_directory(RUNTIME_SCOPE_SYSTEM, "systemd/swtpm", &runtime_dir);
        if (r < 0)
                return log_error_errno(r, "Unable to determine runtime directory: %m");

        _cleanup_free_ char *swtpm = NULL;
        r = find_executable("swtpm", &swtpm);
        if (r < 0)
                return log_error_errno(r, "Failed to find 'swtpm' binary: %m");

        _cleanup_free_ char *_esp = NULL;
        const char *esp;
        if (in_initrd())
                /* The early ESP support uses only a single mount point, we do not need to search for it. */
                esp = "/sysefi";
        else {
                r = find_esp_and_warn(
                                /* root= */ NULL,
                                /* path= */ NULL,
                                /* unprivileged_mode= */ false,
                                &_esp);
                if (r == -ENOKEY) /* This one find_esp_and_warn() doesn't actually log about. */
                        return log_error_errno(r, "No ESP discovered.");
                if (r < 0)
                        return r;
                esp = _esp;
        }

        _cleanup_free_ char *state_dir = NULL;
        _cleanup_close_ int state_fd = -EBADF;
        r = chase("/loader/swtpm",
                  esp, CHASE_PREFIX_ROOT|CHASE_TRIGGER_AUTOFS|CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY,
                  &state_dir,
                  &state_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to open swtpm state directory in ESP: %m");

        _cleanup_(unlink_and_freep) char *secret = NULL;
        r = prepare_secret(runtime_dir, &secret);
        if (r < 0)
                return r;

        r = setup_swtpm(state_dir, state_fd, secret);
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **args =
                strv_new(swtpm,
                         "chardev",
                         "--vtpm-proxy",
                         "--tpm2",
                         /* Make sure that in the initrd swtpm never sends TPM2_Shutdown() for us, we want to
                          * be able to stop the daemon after all temporarily during the initrd→host
                          * transition. */
                         in_initrd() ? "--flags=startup-clear,disable-auto-shutdown" : "--flags=startup-clear");
        if (!args)
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
