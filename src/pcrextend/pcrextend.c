/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-json.h"
#include "sd-messages.h"

#include "build.h"
#include "efi-loader.h"
#include "escape.h"
#include "json-util.h"
#include "main-func.h"
#include "openssl-util.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pcrextend-util.h"
#include "pretty-print.h"
#include "strv.h"
#include "tpm2-pcr.h"
#include "tpm2-util.h"
#include "varlink.h"
#include "varlink-io.systemd.PCRExtend.h"

static bool arg_graceful = false;
static char *arg_tpm2_device = NULL;
static char **arg_banks = NULL;
static char *arg_file_system = NULL;
static bool arg_machine_id = false;
static bool arg_product_id = false;
static unsigned arg_pcr_index = UINT_MAX;
static char *arg_nvpcr_name = NULL;
static bool arg_allocate = false;
static bool arg_delete = false;
static bool arg_varlink = false;
static bool arg_early = false;

STATIC_DESTRUCTOR_REGISTER(arg_banks, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_file_system, freep);
STATIC_DESTRUCTOR_REGISTER(arg_nvpcr_name, freep);

#define EXTENSION_STRING_SAFE_LIMIT 1024

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-pcrextend", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s  [OPTIONS...] WORD\n"
               "%1$s  [OPTIONS...] --allocate\n"
               "%1$s  [OPTIONS...] --delete\n"
               "%1$s  [OPTIONS...] --file-system=PATH\n"
               "%1$s  [OPTIONS...] --machine-id\n"
               "%1$s  [OPTIONS...] --product-id\n"
               "\n%5$sExtend a TPM2 PCR with boot phase, machine ID, or file system ID.%6$s\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help              Show this help\n"
               "     --version           Print version\n"
               "     --bank=DIGEST       Select TPM PCR bank (SHA1, SHA256)\n"
               "     --pcr=INDEX         Select TPM PCR index (0…23)\n"
               "     --nvpcr=NAME        Select TPM PCR mode nvindex name\n"
               "     --allocate          Allocate TPM PCR mode nvindex (if needed)\n"
               "     --delete            Delete TPM PCR mode nvindex\n"
               "     --tpm2-device=PATH  Use specified TPM2 device\n"
               "     --graceful          Exit gracefully if no TPM2 device is found\n"
               "     --file-system=PATH  Measure UUID/labels of file system into PCR 15\n"
               "     --machine-id        Measure machine ID into PCR 15\n"
               "     --product-id        Measure SMBIOS product ID into NvPCR 'hardware'\n"
               "     --early             Run in early boot mode, without access to /var/\n"
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
                ARG_PCR,
                ARG_NVPCR,
                ARG_ALLOCATE,
                ARG_DELETE,
                ARG_TPM2_DEVICE,
                ARG_GRACEFUL,
                ARG_FILE_SYSTEM,
                ARG_MACHINE_ID,
                ARG_PRODUCT_ID,
                ARG_EARLY,
        };

        static const struct option options[] = {
                { "help",        no_argument,       NULL, 'h'             },
                { "version",     no_argument,       NULL, ARG_VERSION     },
                { "bank",        required_argument, NULL, ARG_BANK        },
                { "pcr",         required_argument, NULL, ARG_PCR         },
                { "nvpcr",       required_argument, NULL, ARG_NVPCR       },
                { "allocate",    no_argument,       NULL, ARG_ALLOCATE    },
                { "delete",      no_argument,       NULL, ARG_DELETE      },
                { "tpm2-device", required_argument, NULL, ARG_TPM2_DEVICE },
                { "graceful",    no_argument,       NULL, ARG_GRACEFUL    },
                { "file-system", required_argument, NULL, ARG_FILE_SYSTEM },
                { "machine-id",  no_argument,       NULL, ARG_MACHINE_ID  },
                { "product-id",  no_argument,       NULL, ARG_PRODUCT_ID  },
                { "early",       no_argument,       NULL, ARG_EARLY       },
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

                case ARG_PCR:
                        r = tpm2_pcr_index_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse PCR index: %s", optarg);

                        arg_pcr_index = r;
                        break;

                case ARG_NVPCR:
                        if (!tpm2_nvpcr_name_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "NvPCR name is not valid: %s", optarg);

                        r = free_and_strdup_warn(&arg_nvpcr_name, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_ALLOCATE:
                        arg_allocate = true;
                        break;

                case ARG_DELETE:
                        arg_delete = true;
                        break;

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

                case ARG_GRACEFUL:
                        arg_graceful = true;
                        break;

                case ARG_FILE_SYSTEM:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_file_system);
                        if (r < 0)
                                return r;

                        break;

                case ARG_MACHINE_ID:
                        arg_machine_id = true;
                        break;

                case ARG_PRODUCT_ID:
                        arg_product_id = true;
                        break;

                case ARG_EARLY:
                        arg_early = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (!!arg_file_system + arg_machine_id + arg_product_id + arg_delete > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--file-system=, --machine-id, --product-id, --delete may not be combined.");

        if (arg_pcr_index != UINT_MAX && arg_nvpcr_name)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--pcr= and --nvpcr= may not be combined.");

        if (arg_allocate && arg_delete)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--allocate and --delete may not be combined.");

        r = varlink_invocation(VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0)
                arg_varlink = true;
        else if (arg_pcr_index == UINT_MAX && !arg_nvpcr_name) {
                arg_pcr_index =
                        (arg_file_system || arg_machine_id) ? TPM2_PCR_SYSTEM_IDENTITY : /* → PCR 15 */
                                            !arg_product_id ? TPM2_PCR_KERNEL_BOOT :     /* → PCR 11 */
                                                              UINT_MAX;

                r = free_and_strdup_warn(&arg_nvpcr_name, arg_product_id ? "hardware" : NULL);
                if (r < 0)
                        return r;
        }

        if ((arg_allocate || arg_delete) && !arg_nvpcr_name)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--allocate and --delete require --nvpcr= to be specified.");

        return 1;
}

static int determine_banks(Tpm2Context *c, unsigned target_pcr_nr) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(c);

        if (!strv_isempty(arg_banks)) /* Explicitly configured? Then use that */
                return 0;

        r = tpm2_get_good_pcr_banks_strv(c, UINT32_C(1) << target_pcr_nr, &l);
        if (r < 0)
                return log_error_errno(r, "Could not verify pcr banks: %m");

        strv_free_and_replace(arg_banks, l);
        return 0;
}

static int escape_and_truncate_data(const void *data, size_t size, char **ret) {
        _cleanup_free_ char *safe = NULL;

        assert(data || size == 0);

        if (size > EXTENSION_STRING_SAFE_LIMIT) {
                safe = cescape_length(data, EXTENSION_STRING_SAFE_LIMIT);
                if (!safe)
                        return -ENOMEM;

                if (!strextend(&safe, "..."))
                        return -ENOMEM;
        } else {
                safe = cescape_length(data, size);
                if (!safe)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(safe);
        return 0;
}

static int extend_pcr_now(
                unsigned pcr,
                const void *data,
                size_t size,
                Tpm2UserspaceEventType event) {

        _cleanup_(tpm2_context_unrefp) Tpm2Context *c = NULL;
        int r;

        r = tpm2_context_new_or_warn(arg_tpm2_device, &c);
        if (r < 0)
                return r;

        r = determine_banks(c, pcr);
        if (r < 0)
                return r;
        if (strv_isempty(arg_banks)) /* Still none? */
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Found a TPM2 without enabled PCR banks. Can't operate.");

        _cleanup_free_ char *joined_banks = NULL;
        joined_banks = strv_join(arg_banks, ", ");
        if (!joined_banks)
                return log_oom();

        _cleanup_free_ char *safe = NULL;
        if (escape_and_truncate_data(data, size, &safe) < 0)
                return log_oom();

        log_debug("Measuring '%s' into PCR index %u, banks %s.", safe, pcr, joined_banks);

        r = tpm2_pcr_extend_bytes(c, arg_banks, pcr, &IOVEC_MAKE(data, size), /* secret= */ NULL, event, safe);
        if (r < 0)
                return log_error_errno(r, "Could not extend PCR: %m");

        log_struct(LOG_INFO,
                   "MESSAGE_ID=" SD_MESSAGE_TPM_PCR_EXTEND_STR,
                   LOG_MESSAGE("Extended PCR index %u with '%s' (banks %s).", pcr, safe, joined_banks),
                   "MEASURING=%s", safe,
                   "PCR=%u", pcr,
                   "BANKS=%s", joined_banks);

        return 0;
}

static int extend_nvpcr_now(
                const char *name,
                const void *data,
                size_t size,
                Tpm2UserspaceEventType event,
                bool allocate) {

        _cleanup_(tpm2_context_unrefp) Tpm2Context *c = NULL;
        int r;

        r = tpm2_context_new_or_warn(arg_tpm2_device, &c);
        if (r < 0)
                return r;

        _cleanup_free_ char *safe = NULL;
        if (escape_and_truncate_data(data, size, &safe) < 0)
                return log_oom();

        log_debug("Measuring '%s' into NvPCR index '%s'.", safe, name);

        r = tpm2_nvpcr_extend_bytes(c, name, &IOVEC_MAKE(data, size), /* secret= */ NULL, event, safe);
        if (r == -ENOENT) {
                if (!allocate)
                        return log_error_errno(r, "NvPCR index '%s' does not exist.", name);

                /* NvPCR wasn't allocated yet, but we have been told to allocate it. Do so. */
                _cleanup_(iovec_done_erase) struct iovec anchor_secret = {};
                r = tpm2_nvpcr_acquire_anchor_secret(&anchor_secret, /* sync_secondary= */ !arg_early);
                if (r < 0)
                        return r;

                r = tpm2_nvpcr_allocate(c, /* session= */ NULL, name, /* sync_secondary= */ !arg_early);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate NvPCR index '%s': %m", name);

                r = tpm2_nvpcr_initialize(c, /* session= */ NULL, name, &anchor_secret, /* sync_secondary= */ false);
                if (r < 0)
                        return log_error_errno(r, "Failed to extend NvPCR index '%s' with anchor secret: %m", name);

                r = tpm2_nvpcr_extend_bytes(c, name, &IOVEC_MAKE(data, size), /* secret= */ NULL, event, safe);
        } else if (r == -ENETDOWN) {
                /* NvPCR is defined, but is not anchored yet. Let's do this now. */

                _cleanup_(iovec_done_erase) struct iovec anchor_secret = {};
                r = tpm2_nvpcr_acquire_anchor_secret(&anchor_secret, /* sync_secondary= */ !arg_early);
                if (r < 0)
                        return r;

                r = tpm2_nvpcr_initialize(c, /* session= */ NULL, name, &anchor_secret, /* sync_secondary= */ !arg_early);
                if (r < 0)
                        return log_error_errno(r, "Failed to extend NvPCR index '%s' with anchor secret: %m", name);

                r = tpm2_nvpcr_extend_bytes(c, name, &IOVEC_MAKE(data, size), /* secret= */ NULL, event, safe);
        }
        if (r < 0)
                return log_error_errno(r, "Could not extend NvPCR: %m");

        log_struct(LOG_INFO,
                   "MESSAGE_ID=" SD_MESSAGE_TPM_NVPCR_EXTEND_STR,
                   LOG_MESSAGE("Extended NvPCR index '%s' with '%s'.", name, safe),
                   "MEASURING=%s", safe,
                   "NVPCR=%u", name);

        return 0;
}

static int allocate_nvpcr_now(const char *name) {
        _cleanup_(tpm2_context_unrefp) Tpm2Context *c = NULL;
        int r;

        assert(name);

        r = tpm2_context_new_or_warn(arg_tpm2_device, &c);
        if (r < 0)
                return r;

        r = tpm2_nvpcr_allocate(c, /* session= */ NULL, name, /* sync_secondary= */ !arg_early);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate NvPCR index '%s': %m", name);
        bool is_new = r > 0;
        if (is_new)
                log_info("NvPCR index '%s' successfully allocated.", name);
        else
                log_info("NvPCR index '%s' exists already.", name);

        _cleanup_(iovec_done_erase) struct iovec anchor_secret = {};

        /* The NvPCR is now allocated, now extend the anchor secret to it, if we haven't done so yet. The
         * anchor secret is slow to acquire, hence try without, maybe the NvPCR is already
         * allocated/initialized, and we don't need it */

        if (is_new) {
                /* If the NvPCR is new we definitely need to initialize it */
                r = tpm2_nvpcr_acquire_anchor_secret(&anchor_secret, /* sync_secondary= */ !arg_early);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire NvPCR anchor secret.");
        }

        r = tpm2_nvpcr_initialize(c, /* session= */ NULL, name, &anchor_secret, /* sync_secondary= */ false);
        if (r == -EUNATCH) {
                assert(!iovec_is_set(&anchor_secret));

                /* EUNATCH → We need the anchor secret, as we apparently didn't anchor this yet. */
                r = tpm2_nvpcr_acquire_anchor_secret(&anchor_secret, arg_early);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire NvPCR anchor secret.");

                r = tpm2_nvpcr_initialize(c, /* session= */ NULL, name, &anchor_secret, /* sync_secondary= */ false);
        }
        if (r < 0)
                return log_error_errno(r, "Failed to extend NvPCR index '%s' with anchor secret: %m", name);

        return 0;
}

static int delete_nvpcr_now(const char *name) {
        _cleanup_(tpm2_context_unrefp) Tpm2Context *c = NULL;
        int r;

        assert(name);

        r = tpm2_context_new_or_warn(arg_tpm2_device, &c);
        if (r < 0)
                return r;

        r = tpm2_nvpcr_delete(c, /* session= */ NULL, name, arg_early);
        if (r < 0)
                return log_error_errno(r, "Failed to delete NvPCR index '%s': %m", name);
        if (r == 0)
                log_info("NvPCR index '%s' does not exist.", name);
        else
                log_info("NvPCR index '%s' deleted.", name);

        return 0;
}

typedef struct MethodExtendParameters {
        unsigned pcr;
        const char *nvpcr;
        int allocate;
        const char *text;
        struct iovec data;
} MethodExtendParameters;

static void method_extend_parameters_done(MethodExtendParameters *p) {
        assert(p);

        iovec_done(&p->data);
}

static int vl_method_extend(Varlink *link, sd_json_variant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "pcr",      _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,           offsetof(MethodExtendParameters, pcr),      0 },
                { "nvpcr",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,   offsetof(MethodExtendParameters, nvpcr),    0 },
                { "allocate", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_tristate,       offsetof(MethodExtendParameters, allocate), 0 },
                { "text",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,   offsetof(MethodExtendParameters, text),     0 },
                { "data",     SD_JSON_VARIANT_STRING,        json_dispatch_unbase64_iovec,    offsetof(MethodExtendParameters, data),     0 },
                {}
        };
        _cleanup_(method_extend_parameters_done) MethodExtendParameters p = {
                .pcr = UINT_MAX,
                .allocate = -1,
        };
        int r;

        assert(link);

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.nvpcr) {
                /* Specifying both nvpcr name and pcr doesn't make sense */
                if (p.pcr != UINT_MAX)
                        return varlink_error_invalid_parameter_name(link, "nvpcr");

                if (!tpm2_nvpcr_name_is_valid(p.nvpcr))
                        return varlink_error_invalid_parameter_name(link, "nvpcr");

        } else if (!TPM2_PCR_INDEX_VALID(p.pcr))
                return varlink_error_invalid_parameter_name(link, "pcr");

        struct iovec *extend_iovec, text_iovec;

        if (p.text) {
                /* Specifying both the text string and the binary data is not allowed */
                if (p.data.iov_base)
                        return varlink_error_invalid_parameter_name(link, "data");

                text_iovec = IOVEC_MAKE_STRING(p.text);
                extend_iovec = &text_iovec;

        } else if (p.data.iov_base)
                extend_iovec = &p.data;
        else
                return varlink_error_invalid_parameter_name(link, "text");

        if (p.nvpcr) {
                r = extend_nvpcr_now(p.nvpcr, extend_iovec->iov_base, extend_iovec->iov_len, _TPM2_USERSPACE_EVENT_TYPE_INVALID, p.allocate != 0);
                if (r == -ENOENT)
                        return varlink_error(link, "io.systemd.PCRExtend.NoSuchNvPCR", NULL);
        } else
                r = extend_pcr_now(p.pcr, extend_iovec->iov_base, extend_iovec->iov_len, _TPM2_USERSPACE_EVENT_TYPE_INVALID);
        if (r < 0)
                return r;

        return varlink_reply(link, NULL);
}

typedef struct MethodAllocateNVPCRParameters {
        const char *name;
} MethodAllocateNVExtendParameters;

static int vl_method_allocate_nvpcr(Varlink *link, sd_json_variant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(MethodAllocateNVExtendParameters, name), SD_JSON_MANDATORY },
                {}
        };

        MethodAllocateNVExtendParameters p = {};
        int r;

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!tpm2_nvpcr_name_is_valid(p.name))
                return varlink_error_invalid_parameter_name(link, "name");

        r = allocate_nvpcr_now(p.name);
        if (r < 0)
                return r;

        return varlink_reply(link, NULL);
}

typedef struct MethodDeleteNVPCRParameters {
        const char *name;
} MethodDeleteNVExtendParameters;

static int vl_method_delete_nvpcr(Varlink *link, sd_json_variant *parameters, VarlinkMethodFlags flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, offsetof(MethodDeleteNVExtendParameters, name), SD_JSON_MANDATORY },
                {}
        };

        MethodDeleteNVExtendParameters p = {};
        int r;

        r = varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!tpm2_nvpcr_name_is_valid(p.name))
                return varlink_error_invalid_parameter_name(link, "name");

        r = delete_nvpcr_now(p.name);
        if (r < 0)
                return r;

        return varlink_reply(link, NULL);
}

static int run(int argc, char *argv[]) {
        _cleanup_free_ char *word = NULL;
        Tpm2UserspaceEventType event;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_varlink) {
                _cleanup_(varlink_server_unrefp) VarlinkServer *varlink_server = NULL;

                /* Invocation as Varlink service */

                r = varlink_server_new(&varlink_server, VARLINK_SERVER_ROOT_ONLY);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate Varlink server: %m");

                r = varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_PCRExtend);
                if (r < 0)
                        return log_error_errno(r, "Failed to add Varlink interface: %m");

                r = varlink_server_bind_method_many(
                                varlink_server,
                                "io.systemd.PCRExtend.Extend", vl_method_extend,
                                "io.systemd.PCRExtend.AllocateNvPCR", vl_method_allocate_nvpcr,
                                "io.systemd.PCRExtend.DeleteNvPCR", vl_method_delete_nvpcr);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind Varlink methods: %m");

                r = varlink_server_loop_auto(varlink_server);
                if (r < 0)
                        return log_error_errno(r, "Failed to run Varlink event loop: %m");

                return EXIT_SUCCESS;
        }

        if (arg_file_system) {
                if (optind != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected no argument.");

                r = pcrextend_file_system_word(arg_file_system, &word, NULL);
                if (r < 0)
                        return r;

                event = TPM2_EVENT_FILESYSTEM;

        } else if (arg_machine_id) {

                if (optind != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected no argument.");

                r = pcrextend_machine_id_word(&word);
                if (r < 0)
                        return r;

                event = TPM2_EVENT_MACHINE_ID;

        } else if (arg_product_id)  {

                if (optind != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected no argument.");

                r = pcrextend_product_id_word(&word);
                if (r < 0)
                        return r;

                event = TPM2_EVENT_PRODUCT_ID;

        } else if (arg_delete) {

                if (optind != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected no argument.");

                return delete_nvpcr_now(arg_nvpcr_name);

        } else if (arg_allocate && optind >= argc)
                return allocate_nvpcr_now(arg_nvpcr_name);
        else {
                if (optind+1 != argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected a single argument.");

                word = strdup(argv[optind]);
                if (!word)
                        return log_oom();

                /* Refuse to measure an empty word. We want to be able to write the series of measured words
                 * separated by colons, where multiple separating colons are collapsed. Thus it makes sense to
                 * disallow an empty word to avoid ambiguities. */
                if (isempty(word))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "String to measure cannot be empty, refusing.");

                event = TPM2_EVENT_PHASE;
        }

        if (arg_graceful && tpm2_support() != TPM2_SUPPORT_FULL) {
                log_notice("No complete TPM2 support detected, exiting gracefully.");
                return EXIT_SUCCESS;
        }

        /* Skip logic if sd-stub is not used, after all PCR 11 might have a very different purpose then. */
        r = efi_measured_uki(LOG_ERR);
        if (r < 0)
                return r;
        if (r == 0) {
                log_info("Kernel stub did not measure kernel image into PCR %i, skipping userspace measurement, too.", TPM2_PCR_KERNEL_BOOT);
                return EXIT_SUCCESS;
        }

        if (arg_nvpcr_name)
                r = extend_nvpcr_now(arg_nvpcr_name, word, strlen(word), event, arg_allocate);
        else
                r = extend_pcr_now(arg_pcr_index, word, strlen(word), event);
        if (r < 0)
                return r;

        return EXIT_SUCCESS;
}

DEFINE_MAIN_FUNCTION(run);
