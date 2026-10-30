/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "build.h"
#include "chase.h"
#include "dlopen-note.h"
#include "efi-loader.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "find-esp.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "hmac.h"
#include "initrd-util.h"
#include "inotify-util.h"
#include "io-util.h"
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
#include "tpm2-event-log.h"
#include "tpm2-pcr.h"
#include "tpm2-util.h"
#include "unaligned.h"
#include "utf8.h"
#include "verbs.h"

COMMAND(
        "systemd-tpm2-swtpm\0",
        "Provide a fallback software TPM.",
        .man_pages = "systemd-tpm2-swtpm.service(8)\0",
);

#define BOOT_SECRET_SIZE 32U
#define REPLAY_DEVICE_TIMEOUT_USEC (30 * USEC_PER_SEC)
#define REPLAY_LOG_SIZE_MAX (4U * 1024U * 1024U)

static bool arg_replay = false;

static int parse_argv(int argc, char *argv[]) {
        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("replay", NULL, "Replay the measurements handed over by systemd-stub"):
                        arg_replay = true;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(SD_JSON_FORMAT_OFF);
                }

        if (option_parser_get_n_args(&opts) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program expects no arguments.");

        return 1;
}

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
        _cleanup_close_ int wipe_fd = fd_reopen(state_fd, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (wipe_fd < 0)
                return log_error_errno(wipe_fd, "Failed to reopen swtpm state directory: %m");
        r = rm_rf_children(TAKE_FD(wipe_fd), REMOVE_PHYSICAL, /* root_dev= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to clear incomplete swtpm state directory: %m");

        log_debug("TPM state directory holds no fully manufactured TPM, manufacturing a TPM.");

        return manufacture_swtpm(state_dir, secret);
}

static int wait_for_tpm2_device(char **ret) {
        usec_t deadline = usec_add(now(CLOCK_MONOTONIC), REPLAY_DEVICE_TIMEOUT_USEC);
        int r;

        assert(ret);

        /* We signal readiness before chain-loading swtpm, hence its vTPM device might not exist yet. Thus,
         * wait for the device node to show up in /dev. This can go away once swtpm signals readiness itself
         * after creating the device, see the FIXME in run(). */

        _cleanup_close_ int inotify_fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (inotify_fd < 0)
                return log_error_errno(errno, "Failed to allocate inotify fd: %m");

        r = inotify_add_watch_and_warn(inotify_fd, "/dev", IN_CREATE|IN_ONLYDIR);
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *device = NULL;

                /* The sysfs entry shows up before the device node, hence check for both */
                r = tpm2_find_device_auto(&device);
                if (r >= 0 && access(device, F_OK) >= 0) {
                        *ret = TAKE_PTR(device);
                        return 0;
                }
                if (r < 0 && r != -ENODEV)
                        return log_error_errno(r, "Failed to find the software TPM device: %m");

                usec_t n = now(CLOCK_MONOTONIC);
                if (n >= deadline)
                        return log_error_errno(SYNTHETIC_ERRNO(ETIMEDOUT), "Timed out waiting for the software TPM device.");

                r = fd_wait_for_event(inotify_fd, POLLIN, usec_sub_unsigned(deadline, n));
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for the software TPM device: %m");

                (void) flush_fd(inotify_fd);
        }
}

static int replay_stub_event_log(void) {
        int r;

        /* Without a TPM systemd-stub couldn't measure the UKI, and if systemd.tpm2_measured_os=1 is set, it
         * instead hands over the measurements it would have made as TCG_PCR_EVENT2 records with a single
         * SHA-256 digest. Extend them into the software TPM, so that the PCRs systemd-stub measures into, in
         * particular PCR 11, end up like with a hardware TPM. This must happen before anything else uses the
         * TPM, hence it's done before the service is considered started. In the host the PCRs are restored
         * from the volatile state saved at the end of the initrd. */

        if (!in_initrd()) {
                log_debug("Not running in the initrd, the measurements of systemd-stub were already replayed.");
                return 0;
        }

        /* This is opt-in, like the recording in systemd-stub. Without a firmware TPM, this is only
         * enabled through systemd.tpm2_measured_os=1. */
        if (efi_measured_os(LOG_DEBUG) <= 0) {
                log_debug("OS measurements are not enabled, not replaying the measurements of systemd-stub.");
                return 0;
        }

        _cleanup_free_ char *data = NULL;
        size_t size;
        r = read_full_file_full(
                        AT_FDCWD,
                        "/.extra/tpm2-event-log",
                        UINT64_MAX,
                        REPLAY_LOG_SIZE_MAX,
                        READ_FULL_FILE_VERIFY_REGULAR|READ_FULL_FILE_FAIL_WHEN_LARGER,
                        /* bind_name= */ NULL,
                        &data,
                        &size);
        if (r == -ENOENT) {
                /* PCR 11 won't reach the signed values then, hence binding to them will fail later */
                log_warning("OS measurements are enabled, but systemd-stub handed over no measurements, "
                            "proceeding without replaying them. Is systemd-stub too old?");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read event log of systemd-stub: %m");

        _cleanup_free_ char *device = NULL;
        r = wait_for_tpm2_device(&device);
        if (r < 0)
                return r;

        _cleanup_(tpm2_context_unrefp) Tpm2Context *c = NULL;
        r = tpm2_context_new_or_warn(device, &c);
        if (r < 0)
                return r;

        /* Each record carries a single SHA-256 digest, followed by the event size */
        const size_t digest_offset =
                offsetof(TCG_PCR_EVENT2, digests.digests) + offsetof(packed_TPMT_HA, digest);
        const size_t header_size = digest_offset + SHA256_DIGEST_SIZE + sizeof(uint32_t);

        size_t n = 0;
        for (const uint8_t *p = (const uint8_t*) data, *e = p + size; p < e; n++) {
                if ((size_t) (e - p) < header_size)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Truncated record in event log of systemd-stub.");

                const TCG_PCR_EVENT2 *record = (const TCG_PCR_EVENT2*) p;
                const uint8_t *digest = p + digest_offset;
                uint32_t pcr_index = record->pcrIndex;
                uint32_t event_type = record->eventType;
                uint32_t event_size = unaligned_read_ne32(digest + SHA256_DIGEST_SIZE);
                p += header_size;

                /* systemd-stub only records the PCRs owned by the OS, refuse to touch any others */
                if (!IN_SET(pcr_index, TPM2_PCR_KERNEL_BOOT, TPM2_PCR_KERNEL_CONFIG, TPM2_PCR_SYSEXTS))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected PCR %" PRIu32 " in event log of systemd-stub.", pcr_index);
                if (record->digests.count != 1 || record->digests.digests[0].hashAlg != TPM2_ALG_SHA256)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected digests in event log of systemd-stub.");
                if (event_size > (size_t) (e - p))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Truncated event in event log of systemd-stub.");

                const uint8_t *event = p;
                p += event_size;

                /* The event data is the UTF-16 description, prefixed by the tag for tagged events */
                if (event_type == EV_EVENT_TAG) {
                        const TCG_PCClientTaggedEvent *tag = (const TCG_PCClientTaggedEvent*) event;
                        const size_t tag_size = offsetof(TCG_PCClientTaggedEvent, taggedEventData);

                        if (event_size < tag_size || tag->taggedEventDataSize != event_size - tag_size)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Invalid tagged event in event log of systemd-stub.");

                        event = tag->taggedEventData;
                        event_size = tag->taggedEventDataSize;
                } else if (event_type != EV_IPL)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected event type 0x%" PRIx32 " in event log of systemd-stub.", event_type);

                _cleanup_free_ char *description = utf16_to_utf8((const char16_t*) (const void*) event, event_size);
                if (!description)
                        return log_oom();

                TPML_DIGEST_VALUES values = {
                        .count = 1,
                        .digests[0].hashAlg = TPM2_ALG_SHA256,
                };
                memcpy(values.digests[0].digest.sha256, digest, SHA256_DIGEST_SIZE);

                r = tpm2_pcr_extend_digests(c, pcr_index, &values, _TPM2_USERSPACE_EVENT_TYPE_INVALID, description);
                if (r < 0)
                        return log_error_errno(r, "Failed to replay measurement '%s' into PCR %" PRIu32 ": %m", description, pcr_index);
        }

        log_info("Replayed %zu measurements of systemd-stub into the software TPM.", n);
        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        LIBBLKID_NOTE(recommended);
        LIBCRYPTO_NOTE(suggested);
        TPM2_NOTE(suggested);

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_replay)
                return replay_stub_event_log();

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
