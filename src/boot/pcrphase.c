/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include <sd-device.h>
#include <sd-messages.h>

#include "blockdev-util.h"
#include "build.h"
#include "chase-symlinks.h"
#include "efi-loader.h"
#include "efivars.h"
#include "escape.h"
#include "fd-util.h"
#include "main-func.h"
#include "mountpoint-util.h"
#include "openssl-util.h"
#include "parse-argument.h"
#include "pretty-print.h"
#include "tpm-pcr.h"
#include "tpm2-util.h"

static char *arg_tpm2_device = NULL;
static char **arg_banks = NULL;
static char *arg_file_system = NULL;
static bool arg_machine_id = false;

STATIC_DESTRUCTOR_REGISTER(arg_banks, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_file_system, freep);

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-pcrphase", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s  [OPTIONS...] WORD\n"
               "%1$s  [OPTIONS...] --file-system=PATH\n"
               "%1$s  [OPTIONS...] --machine-id\n"
               "\n%5$sMeasure boot phase into TPM2 PCR 11.%6$s\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help              Show this help\n"
               "     --version           Print version\n"
               "     --bank=DIGEST       Select TPM bank (SHA1, SHA256)\n"
               "     --tpm2-device=PATH  Use specified TPM2 device\n"
               "     --file-system=PATH  Measure UUID/labels of file system into PCR 15\n"
               "     --machine-id        Measure machine ID into PCR 15\n"
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
                ARG_BANK,
                ARG_TPM2_DEVICE,
                ARG_FILE_SYSTEM,
                ARG_MACHINE_ID,
        };

        static const struct option options[] = {
                { "help",        no_argument,       NULL, 'h'             },
                { "version",     no_argument,       NULL, ARG_VERSION     },
                { "bank",        required_argument, NULL, ARG_BANK        },
                { "tpm2-device", required_argument, NULL, ARG_TPM2_DEVICE },
                { "file-system", required_argument, NULL, ARG_FILE_SYSTEM },
                { "machine-id",  no_argument,       NULL, ARG_MACHINE_ID  },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help(0, NULL, NULL);
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_BANK: {
                        const EVP_MD *implementation;

                        implementation = EVP_get_digestbyname(optarg);
                        if (!implementation)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown bank '%s', refusing.", optarg);

                        if (strv_extend(&arg_banks, EVP_MD_name(implementation)) < 0)
                                return log_oom();

                        break;
                }

                case ARG_TPM2_DEVICE: {
                        _cleanup_free_ char *device = NULL;

                        if (streq(optarg, "list"))
                                return tpm2_list_devices();

                        if (!streq(optarg, "auto")) {
                                device = strdup(optarg);
                                if (!device)
                                        return log_oom();
                        }

                        free_and_replace(arg_tpm2_device, device);
                        break;
                }

                case ARG_FILE_SYSTEM:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_file_system);
                        if (r < 0)
                                return r;

                        break;

                case ARG_MACHINE_ID:
                        arg_machine_id = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_file_system && arg_machine_id)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--file-system= and --machine-id= may not be combined.");

        return 1;
}

static int determine_banks(struct tpm2_context *c, unsigned target_pcr_nr) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(c);

        if (!strv_isempty(arg_banks)) /* Explicitly configured? Then use that */
                return 0;

        r = tpm2_get_good_pcr_banks_strv(c->esys_context, UINT32_C(1) << target_pcr_nr, &l);
        if (r < 0)
                return r;

        strv_free_and_replace(arg_banks, l);
        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(tpm2_context_destroy) struct tpm2_context c = {};
        _cleanup_free_ char *joined = NULL, *word = NULL;
        unsigned target_pcr_nr;
        size_t length;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_file_system) {
                _cleanup_free_ char *normalized = NULL, *normalized_escaped = NULL;
                _cleanup_(sd_device_unrefp) sd_device *d = NULL;
                _cleanup_strv_free_ char **l = NULL;
                _cleanup_close_ int dfd = -1;

                if (optind != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected no argument.");

                dfd = chase_symlinks_and_open(arg_file_system, NULL, 0, O_DIRECTORY|O_CLOEXEC, &normalized);
                if (dfd < 0)
                        return log_error_errno(dfd, "Failed to open path '%s': %m", arg_file_system);

                r = fd_is_mount_point(dfd, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine if path '%s' is mount point: %m", normalized);
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTDIR), "Specified path '%s' is not a mount point, refusing: %m", normalized);

                r = block_device_new_from_fd(dfd, BLOCK_DEVICE_LOOKUP_BACKING, &d);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine backing block device of '%s': %m", arg_file_system);

                l = strv_new("file-system");
                if (!l)
                        return log_oom();

                normalized_escaped = xescape(normalized, ":"); /* Avoid ambiguity around ":" */
                if (!normalized_escaped)
                        return log_oom();

                r = strv_consume(&l, TAKE_PTR(normalized_escaped));
                if (r < 0)
                        return log_oom();

                FOREACH_STRING(p, "ID_FS_TYPE", "ID_FS_UUID", "ID_FS_LABEL", "ID_PART_ENTRY_UUID", "ID_PART_ENTRY_NAME") {
                        _cleanup_free_ char *escaped = NULL;
                        const char *v = NULL;

                        r = sd_device_get_property_value(d, p, &v);
                        if (r < 0)
                                log_debug_errno(r, "Failed to read %s field off backing block device, ignoring: %m", p);

                        escaped = xescape(strempty(v), ":"); /* Avoid ambiguity around ":" */
                        if (!escaped)
                                return log_oom();

                        r = strv_consume(&l, TAKE_PTR(escaped));
                        if (r < 0)
                                return log_oom();
                }

                assert(strv_length(l) == 7); /* We always want 7 components, to avoid ambiguous strings */

                word = strv_join(l, ":");
                if (!word)
                        return log_oom();

                target_pcr_nr = TPM_PCR_INDEX_VOLUME_KEY; /* → PCR 15 */

        } else if (arg_machine_id) {
                sd_id128_t mid;

                if (optind != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected no argument.");

                r = sd_id128_get_machine(&mid);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire machine ID: %m");

                word = strjoin("machine-id:", SD_ID128_TO_STRING(mid));
                if (!word)
                        return log_oom();

                target_pcr_nr = TPM_PCR_INDEX_VOLUME_KEY; /* → PCR 15 */

        } else {
                if (optind+1 != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected a single argument.");

                word = argv[optind];

                /* Refuse to measure an empty word. We want to be able to write the series of measured words
                 * separated by colons, where multiple separating colons are collapsed. Thus it makes sense to
                 * disallow an empty word to avoid ambiguities. */
                if (isempty(word))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "String to measure cannot be empty, refusing.");

                target_pcr_nr = TPM_PCR_INDEX_KERNEL_IMAGE; /* → PCR 11 */
        }

        length = strlen(word);

        /* Skip logic if sd-stub is not used, after all PCR 11 might have a very different purpose then. */
        r = efi_stub_measured();
        if (r < 0)
                return log_error_errno(r, "Failed to detect if we are running on a kernel image with TPM measurement enabled: %m");
        if (r == 0) {
                log_info("Kernel stub did not measure kernel image into PCR %u, skipping userspace measurement, too.", TPM_PCR_INDEX_KERNEL_IMAGE);
                return EXIT_SUCCESS;
        }

        r = dlopen_tpm2();
        if (r < 0)
                return log_error_errno(r, "Failed to load TPM2 libraries: %m");

        r = tpm2_context_init(arg_tpm2_device, &c);
        if (r < 0)
                return r;

        r = determine_banks(&c, target_pcr_nr);
        if (r < 0)
                return r;
        if (strv_isempty(arg_banks)) /* Still none? */
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Found a TPM2 without enabled PCR banks. Can't operate.");

        joined = strv_join(arg_banks, ", ");
        if (!joined)
                return log_oom();

        log_debug("Measuring '%s' into PCR index %u, banks %s.", word, target_pcr_nr, joined);

        r = tpm2_extend_bytes(c.esys_context, arg_banks, target_pcr_nr, word, length, NULL, 0);
        if (r < 0)
                return r;

        log_struct(LOG_INFO,
                   "MESSAGE_ID=" SD_MESSAGE_TPM_PCR_EXTEND_STR,
                   LOG_MESSAGE("Extended PCR index %u with '%s' (banks %s).", target_pcr_nr, word, joined),
                   "MEASURING=%s", word,
                   "PCR=%u", target_pcr_nr,
                   "BANKS=%s", joined);

        return EXIT_SUCCESS;
}

DEFINE_MAIN_FUNCTION(run);
