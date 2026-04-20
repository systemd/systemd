/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-messages.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "build.h"
#include "crypto-util.h"
#include "efi-loader.h"
#include "escape.h"
#include "format-table.h"
#include "json-util.h"
#include "main-func.h"
#include "options.h"
#include "parse-argument.h"
#include "pcrextend-util.h"
#include "pretty-print.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tpm2-pcr.h"
#include "tpm2-util.h"
#include "varlink-io.systemd.PCRExtend.h"
#include "varlink-util.h"

static bool arg_graceful = false;
static char *arg_tpm2_device = NULL;
static char **arg_banks = NULL;
static char *arg_file_system = NULL;
static bool arg_machine_id = false;
static bool arg_product_id = false;
static uint32_t arg_pcr_mask = 0;
static char *arg_nvpcr_name = NULL;
static bool arg_varlink = false;
static bool arg_early = false;
static Tpm2UserspaceEventType arg_event_type = _TPM2_USERSPACE_EVENT_TYPE_INVALID;

STATIC_DESTRUCTOR_REGISTER(arg_banks, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_file_system, freep);
STATIC_DESTRUCTOR_REGISTER(arg_nvpcr_name, freep);

#define EXTENSION_STRING_SAFE_LIMIT 1024

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = terminal_urlify_man("systemd-pcrextend", "8", &link);
        if (r < 0)
                return log_oom();

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        printf("%1$s  [OPTIONS...] WORD\n"
               "%1$s  [OPTIONS...] --file-system=PATH\n"
               "%1$s  [OPTIONS...] --machine-id\n"
               "%1$s  [OPTIONS...] --product-id\n"
               "\n%2$sExtend a TPM2 PCR with boot phase, machine ID, or file system ID.%3$s\n",
               program_invocation_short_name,
               ansi_highlight(),
               ansi_normal());

        printf("\n%sOptions:%s\n",
               ansi_underline(),
               ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);

        OptionParser state = { argc, argv };
        const char *arg;
        int r;

        FOREACH_OPTION(&state, c, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("bank", "DIGEST", "Select TPM PCR bank (SHA1, SHA256)"): {
                        const EVP_MD *implementation;

                        r = dlopen_libcrypto(LOG_ERR);
                        if (r < 0)
                                return r;

                        implementation = sym_EVP_get_digestbyname(arg);
                        if (!implementation)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown bank '%s', refusing.", arg);

                        if (strv_extend(&arg_banks, sym_EVP_MD_get0_name(implementation)) < 0)
                                return log_oom();

                        break;
                }

                OPTION_LONG("pcr", "INDEX", "Select TPM PCR index (0…23)"):
                        if (isempty(arg)) {
                                arg_pcr_mask = 0;
                                break;
                        }

                        r = tpm2_pcr_index_from_string(arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse PCR index: %s", arg);

                        arg_pcr_mask |= INDEX_TO_MASK(uint32_t, r);
                        break;

                OPTION_LONG("nvpcr", "NAME", "Select TPM PCR mode nvindex name"):
                        if (!tpm2_nvpcr_name_is_valid(arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "NvPCR name is not valid: %s", arg);

                        r = free_and_strdup_warn(&arg_nvpcr_name, arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("tpm2-device", "PATH", "Use specified TPM2 device"): {
                        _cleanup_free_ char *device = NULL;

                        if (streq(arg, "list"))
                                return tpm2_list_devices(/* legend= */ true, /* quiet= */ false);

                        if (!streq(arg, "auto")) {
                                device = strdup(arg);
                                if (!device)
                                        return log_oom();
                        }

                        free_and_replace(arg_tpm2_device, device);
                        break;
                }

                OPTION_LONG("graceful", NULL,
                            "Exit gracefully if no TPM2 device is found"):
                        arg_graceful = true;
                        break;

                OPTION_LONG("file-system", "PATH",
                            "Measure UUID/labels of file system into PCR 15"):
                        r = parse_path_argument(arg, /* suppress_root= */ false, &arg_file_system);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("machine-id", NULL, "Measure machine ID into PCR 15"):
                        arg_machine_id = true;
                        break;

                OPTION_LONG("product-id", NULL,
                            "Measure SMBIOS product ID into NvPCR 'hardware'"):
                        arg_product_id = true;
                        break;

                OPTION_LONG("early", NULL,
                            "Run in early boot mode, without access to /var/"):
                        arg_early = true;
                        break;

                OPTION_LONG("event-type", "TYPE",
                            "Event type to include in the event log"):
                        if (streq(arg, "help"))
                                return DUMP_STRING_TABLE(tpm2_userspace_event_type, Tpm2UserspaceEventType, _TPM2_USERSPACE_EVENT_TYPE_MAX);

                        arg_event_type = tpm2_userspace_event_type_from_string(arg);
                        if (arg_event_type < 0)
                                return log_error_errno(arg_event_type, "Failed to parse --event-type= argument: %s", arg);
                        break;
                }

        if (!!arg_file_system + arg_machine_id + arg_product_id > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--file-system=, --machine-id, --product-id may not be combined.");

        if (arg_pcr_mask != 0 && arg_nvpcr_name)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--pcr= and --nvpcr= may not be combined.");

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0)
                arg_varlink = true;
        else if (arg_pcr_mask == 0 && !arg_nvpcr_name) {
                arg_pcr_mask =
                        (arg_file_system || arg_machine_id) ? INDEX_TO_MASK(uint32_t, TPM2_PCR_SYSTEM_IDENTITY) : /* → PCR 15 */
                                           !arg_product_id  ? INDEX_TO_MASK(uint32_t, TPM2_PCR_KERNEL_BOOT) :     /* → PCR 11 */
                                                              0;

                r = free_and_strdup_warn(&arg_nvpcr_name, arg_product_id ? "hardware" : NULL);
                if (r < 0)
                        return r;
        }

        *ret_args = option_parser_get_args(&state);
        return 1;
}

static int determine_banks(Tpm2Context *c, uint32_t target_pcr_mask) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(c);

        if (!strv_isempty(arg_banks)) /* Explicitly configured? Then use that */
                return 0;

        r = tpm2_get_good_pcr_banks_strv(c, target_pcr_mask, &l);
        if (r < 0)
                return log_error_errno(r, "Could not verify pcr banks: %m");

        strv_free_and_replace(arg_banks, l);
        return 0;
}

static int escape_and_truncate_data(const void *data, size_t size, char **ret) {
        _cleanup_free_ char *safe = NULL;

        assert(data || size == 0);
        assert(ret);

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
                uint32_t pcr_mask,
                const void *data,
                size_t size,
                Tpm2UserspaceEventType event) {

        _cleanup_(tpm2_context_unrefp) Tpm2Context *c = NULL;
        int r;

        assert(pcr_mask != 0);

        r = tpm2_context_new_or_warn(arg_tpm2_device, &c);
        if (r < 0)
                return r;

        r = determine_banks(c, pcr_mask);
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

        BIT_FOREACH(pcr, pcr_mask) {
                log_debug("Measuring '%s' into PCR index %i, banks %s.", safe, pcr, joined_banks);

                r = tpm2_pcr_extend_bytes(c, arg_banks, pcr, &IOVEC_MAKE(data, size), /* secret= */ NULL, event, safe);
                if (r < 0)
                        return log_error_errno(r, "Could not extend PCR: %m");

                log_struct(LOG_INFO,
                           LOG_MESSAGE_ID(SD_MESSAGE_TPM_PCR_EXTEND_STR),
                           LOG_MESSAGE("Extended PCR index %i with '%s' (banks %s).", pcr, safe, joined_banks),
                           LOG_ITEM("MEASURING=%s", safe),
                           LOG_ITEM("PCR=%i", pcr),
                           LOG_ITEM("BANKS=%s", joined_banks));
        }

        return 0;
}

static int extend_nvpcr_now(
                const char *name,
                const void *data,
                size_t size,
                Tpm2UserspaceEventType event) {

        _cleanup_(tpm2_context_unrefp) Tpm2Context *c = NULL;
        int r;

        assert(name);

        r = tpm2_context_new_or_warn(arg_tpm2_device, &c);
        if (r < 0)
                return r;

        _cleanup_free_ char *safe = NULL;
        if (escape_and_truncate_data(data, size, &safe) < 0)
                return log_oom();

        log_debug("Measuring '%s' into NvPCR index '%s'.", safe, name);

        r = tpm2_nvpcr_extend_bytes(c, /* session= */ NULL, name, &IOVEC_MAKE(data, size), /* secret= */ NULL, event, safe);
        if (r == -ENETDOWN) {
                /* NvPCR is not initialized yet. Let's do this now. */

                _cleanup_(iovec_done_erase) struct iovec anchor_secret = {};
                r = tpm2_nvpcr_acquire_anchor_secret(&anchor_secret, /* sync_secondary= */ !arg_early);
                if (r < 0)
                        return r;

                r = tpm2_nvpcr_initialize(c, /* session= */ NULL, name, &anchor_secret);
                if (r < 0)
                        return log_error_errno(r, "Failed to extend NvPCR index '%s' with anchor secret: %m", name);

                r = tpm2_nvpcr_extend_bytes(c, /* session= */ NULL, name, &IOVEC_MAKE(data, size), /* secret= */ NULL, event, safe);
        }
        if (r < 0)
                return log_error_errno(r, "Could not extend NvPCR: %m");

        log_struct(LOG_INFO,
                   "MESSAGE_ID=" SD_MESSAGE_TPM_NVPCR_EXTEND_STR,
                   LOG_MESSAGE("Extended NvPCR index '%s' with '%s'.", name, safe),
                   "MEASURING=%s", safe,
                   "NVPCR=%s", name);

        return 0;
}

typedef struct MethodExtendParameters {
        unsigned pcr;
        const char *nvpcr;
        const char *text;
        struct iovec data;
        Tpm2UserspaceEventType event_type;
} MethodExtendParameters;

static void method_extend_parameters_done(MethodExtendParameters *p) {
        assert(p);

        iovec_done(&p->data);
}

static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_tpm2_userspace_event_type, Tpm2UserspaceEventType, tpm2_userspace_event_type_from_string);

static int vl_method_extend(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "pcr",       _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,                   offsetof(MethodExtendParameters, pcr),   0 },
                { "nvpcr",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,           offsetof(MethodExtendParameters, nvpcr), 0 },
                { "text",      SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,           offsetof(MethodExtendParameters, text),  0 },
                { "data",      SD_JSON_VARIANT_STRING,        json_dispatch_unbase64_iovec,            offsetof(MethodExtendParameters, data),   0 },
                { "eventType", SD_JSON_VARIANT_STRING,        json_dispatch_tpm2_userspace_event_type, offsetof(MethodExtendParameters, event_type), 0 },
                {}
        };
        _cleanup_(method_extend_parameters_done) MethodExtendParameters p = {
                .pcr = UINT_MAX,
                .event_type = _TPM2_USERSPACE_EVENT_TYPE_INVALID,
        };
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.nvpcr) {
                /* Specifying both nvpcr name and pcr doesn't make sense */
                if (p.pcr != UINT_MAX)
                        return sd_varlink_error_invalid_parameter_name(link, "nvpcr");

                if (!tpm2_nvpcr_name_is_valid(p.nvpcr))
                        return sd_varlink_error_invalid_parameter_name(link, "nvpcr");

        } else if (!TPM2_PCR_INDEX_VALID(p.pcr))
                return sd_varlink_error_invalid_parameter_name(link, "pcr");

        struct iovec *extend_iovec, text_iovec;

        if (p.text) {
                /* Specifying both the text string and the binary data is not allowed */
                if (p.data.iov_base)
                        return sd_varlink_error_invalid_parameter_name(link, "data");

                text_iovec = IOVEC_MAKE_STRING(p.text);
                extend_iovec = &text_iovec;

        } else if (p.data.iov_base)
                extend_iovec = &p.data;
        else
                return sd_varlink_error_invalid_parameter_name(link, "text");

        if (p.nvpcr) {
                r = extend_nvpcr_now(p.nvpcr, extend_iovec->iov_base, extend_iovec->iov_len, p.event_type);
                if (r == -ENOENT)
                        return sd_varlink_error(link, "io.systemd.PCRExtend.NoSuchNvPCR", NULL);
        } else
                r = extend_pcr_now(INDEX_TO_MASK(uint32_t, p.pcr), extend_iovec->iov_base, extend_iovec->iov_len, p.event_type);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        int r;

        r = varlink_server_new(&varlink_server, SD_VARLINK_SERVER_ROOT_ONLY, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_PCRExtend);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method(varlink_server, "io.systemd.PCRExtend.Extend", vl_method_extend);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_free_ char *word = NULL;
        Tpm2UserspaceEventType event = _TPM2_USERSPACE_EVENT_TYPE_INVALID;
        int r;

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        size_t n_args = strv_length(args);

        if (arg_varlink)
                return vl_server(); /* Invocation as Varlink service */

        if (arg_file_system) {
                if (n_args != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected no argument.");

                r = pcrextend_file_system_word(arg_file_system, &word, NULL);
                if (r < 0)
                        return r;

                event = TPM2_EVENT_FILESYSTEM;

        } else if (arg_machine_id) {

                if (n_args != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected no argument.");

                r = pcrextend_machine_id_word(&word);
                if (r < 0)
                        return r;

                event = TPM2_EVENT_MACHINE_ID;

        } else if (arg_product_id)  {

                if (n_args != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected no argument.");

                r = pcrextend_product_id_word(&word);
                if (r < 0)
                        return r;

                event = TPM2_EVENT_PRODUCT_ID;
        } else {
                if (n_args != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected a single argument.");

                word = strdup(args[0]);
                if (!word)
                        return log_oom();

                /* Refuse to measure an empty word. We want to be able to write the series of measured words
                 * separated by colons, where multiple separating colons are collapsed. Thus it makes sense to
                 * disallow an empty word to avoid ambiguities. */
                if (isempty(word))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "String to measure cannot be empty, refusing.");

                event = TPM2_EVENT_PHASE;
        }

        /* Override with explicitly configured event type */
        if (arg_event_type >= 0)
                event = arg_event_type;

        if (arg_graceful && !tpm2_is_mostly_supported()) {
                log_notice("No complete TPM2 support detected, exiting gracefully.");
                return EXIT_SUCCESS;
        }

        /* Skip logic if measured OS functionality is not enabled. */
        r = efi_measured_os(LOG_ERR);
        if (r < 0)
                return r;
        if (r == 0) {
                log_info("OS measurements not explicitly requested and kernel stub did not measure kernel image into PCR %i, skipping userspace measurement, too.", TPM2_PCR_KERNEL_BOOT);
                return EXIT_SUCCESS;
        }

        if (arg_nvpcr_name)
                r = extend_nvpcr_now(arg_nvpcr_name, word, strlen(word), event);
        else
                r = extend_pcr_now(arg_pcr_mask, word, strlen(word), event);
        if (r < 0)
                return r;

        return EXIT_SUCCESS;
}

DEFINE_MAIN_FUNCTION(run);
