/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "build.h"
#include "crypto-util.h"
#include "efi-loader.h"
#include "efivars.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "hexdecoct.h"
#include "log.h"
#include "main-func.h"
#include "options.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "tpm2-pcr.h"
#include "tpm2-util.h"
#include "uki.h"
#include "verbs.h"

/* Tool for pre-calculating expected TPM PCR values based on measured resources. This is intended to be used
 * to pre-calculate suitable values for PCR 11, the way sd-stub measures into it. */

static char *arg_sections[_UNIFIED_SECTION_MAX] = {};
static char **arg_banks = NULL;
static char *arg_tpm2_device = NULL;
static char *arg_private_key = NULL;
static KeySourceType arg_private_key_source_type = OPENSSL_KEY_SOURCE_FILE;
static char *arg_private_key_source = NULL;
static char *arg_public_key = NULL;
static char *arg_certificate = NULL;
static char *arg_certificate_source = NULL;
static CertificateSourceType arg_certificate_source_type = OPENSSL_CERTIFICATE_SOURCE_FILE;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO|SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_current = false;
static char **arg_phase = NULL;
static char *arg_append = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_banks, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_tpm2_device, freep);
STATIC_DESTRUCTOR_REGISTER(arg_private_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_private_key_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_public_key, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate, freep);
STATIC_DESTRUCTOR_REGISTER(arg_certificate_source, freep);
STATIC_DESTRUCTOR_REGISTER(arg_phase, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_append, freep);

static void free_sections(char*(*sections)[_UNIFIED_SECTION_MAX]) {
        for (UnifiedSection c = 0; c < _UNIFIED_SECTION_MAX; c++)
                free((*sections)[c]);
}

STATIC_DESTRUCTOR_REGISTER(arg_sections, free_sections);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        _cleanup_(table_unrefp) Table *verbs = NULL, *options = NULL, *options2 = NULL;
        int r;

        r = terminal_urlify_man("systemd-measure", "1", &link);
        if (r < 0)
                return log_oom();

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        r = option_parser_get_help_table(&options);
        if (r < 0)
                return r;

        r = option_parser_get_help_table_group("UKI PE Section Options", &options2);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, options, options2);

        printf("%s [OPTIONS...] COMMAND ...\n"
               "\n%sPre-calculate and sign PCR hash for a unified kernel image (UKI).%s\n"
               "\n%sCommands:%s\n",
               program_invocation_short_name,
               ansi_highlight(), ansi_normal(),
               ansi_underline(), ansi_normal());

        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        printf("\n%sOptions:%s\n", ansi_underline(), ansi_normal());

        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        printf("\n%sUKI PE Section Options:%s\n", ansi_underline(), ansi_normal());

        r = table_print_or_warn(options2);
        if (r < 0)
                return r;

        printf("\nSee the %s for details.\n", link);
        return 0;
}

VERB_COMMON_HELP_HIDDEN(help);

static char *normalize_phase(const char *s) {
        _cleanup_strv_free_ char **l = NULL;

        /* Let's normalize phase expressions. We split the series of colon-separated words up, then remove
         * all empty ones, and glue them back together again. In other words we remove duplicate ":", as well
         * as leading and trailing ones. */

        l = strv_split(s, ":"); /* Split series of words */
        if (!l)
                return NULL;

        /* Remove all empty words and glue things back together */
        return strv_join(strv_remove(l, ""), ":");
}

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser state = { argc, argv };
        const Option *opt;
        const char *arg;
        int r;

        FOREACH_OPTION_FULL(&state, c, &opt, &arg, /* on_error= */ return c)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION('c', "current", NULL,
                       "Use current PCR values"):
                        arg_current = true;
                        break;

                OPTION_LONG("phase", "PHASE",
                            "Specify a boot phase to sign for"): {
                        char *n;

                        n = normalize_phase(arg);
                        if (!n)
                                return log_oom();

                        r = strv_consume(&arg_phase, TAKE_PTR(n));
                        if (r < 0)
                                return r;

                        break;
                }

                OPTION_LONG("bank", "DIGEST",
                            "Select TPM bank (SHA1, SHA256, SHA384, SHA512)"): {
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

                OPTION_LONG("tpm2-device", "PATH",
                            "Use specified TPM2 device"): {
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

                OPTION_COMMON_PRIVATE_KEY("Private key (PEM) to sign with"):
                        r = free_and_strdup_warn(&arg_private_key, arg);
                        if (r < 0)
                                return r;

                        break;

                OPTION_COMMON_PRIVATE_KEY_SOURCE:
                        r = parse_openssl_key_source_argument(
                                        arg,
                                        &arg_private_key_source,
                                        &arg_private_key_source_type);
                        if (r < 0)
                                return r;

                        break;

                OPTION_LONG("public-key", "KEY",
                            "Public key (PEM) to validate against"):
                        r = parse_path_argument(arg, /* suppress_root= */ false, &arg_public_key);
                        if (r < 0)
                                return r;

                        break;

                OPTION_COMMON_CERTIFICATE("PEM certificate to use for signing"):
                        r = free_and_strdup_warn(&arg_certificate, arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_CERTIFICATE_SOURCE:
                        r = parse_openssl_certificate_source_argument(
                                        arg,
                                        &arg_certificate_source,
                                        &arg_certificate_source_type);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                OPTION_COMMON_LOWERCASE_J:
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                OPTION_LONG("append", "PATH",
                            "Load specified JSON signature, and append new signature to it"):
                        r = parse_path_argument(arg, /* suppress_root= */ false, &arg_append);
                        if (r < 0)
                                return r;

                        break;

                OPTION_GROUP("UKI PE Section Options"): {}

                OPTION_LONG_DATA("linux", "PATH", UNIFIED_SECTION_LINUX,
                                 "Path to Linux kernel image file (→ .linux)"): {}
                OPTION_LONG_DATA("osrel", "PATH", UNIFIED_SECTION_OSREL,
                                 "Path to os-release file (→ .osrel)"): {}
                OPTION_LONG_DATA("cmdline", "PATH", UNIFIED_SECTION_CMDLINE,
                                 "Path to file with kernel command line (→ .cmdline)"): {}
                OPTION_LONG_DATA("initrd", "PATH", UNIFIED_SECTION_INITRD,
                                 "Path to initrd image file (→ .initrd)"): {}
                OPTION_LONG_DATA("ucode", "PATH", UNIFIED_SECTION_UCODE,
                                 "Path to microcode image file (→ .ucode)"): {}
                OPTION_LONG_DATA("splash", "PATH", UNIFIED_SECTION_SPLASH,
                                 "Path to splash bitmap file (→ .splash)"): {}
                OPTION_LONG_DATA("dtb", "PATH", UNIFIED_SECTION_DTB,
                                 "Path to DeviceTree file (→ .dtb)"): {}
                OPTION_LONG_DATA("dtbauto", "PATH", UNIFIED_SECTION_DTBAUTO,
                                 "Path to DeviceTree file for auto selection (→ .dtbauto)"): {}
                OPTION_LONG_DATA("uname", "PATH", UNIFIED_SECTION_UNAME,
                                 "Path to 'uname -r' file (→ .uname)"): {}
                OPTION_LONG_DATA("sbat", "PATH", UNIFIED_SECTION_SBAT,
                                 "Path to SBAT file (→ .sbat)"): {}
                /* The .pcrsig section is not input for signing, hence not actually an argument here */
                OPTION_LONG_DATA("pcrpkey", "PATH", UNIFIED_SECTION_PCRPKEY,
                                 "Path to public key for PCR signatures (→ .pcrpkey)"): {}
                OPTION_LONG_DATA("profile", "PATH", UNIFIED_SECTION_PROFILE,
                                 "Path to profile file (→ .profile)"): {}
                OPTION_LONG_DATA("hwids", "PATH", UNIFIED_SECTION_HWIDS,
                                 "Path to HWIDs file (→ .hwids)"): {}
                OPTION_LONG_DATA("efifw", "PATH", UNIFIED_SECTION_EFIFW,
                                 "Path to EFI firmware file (→ .efifw)"): {}
                        /* Make sure that if new sections are added, the list here is updated. */
                        assert_cc(UNIFIED_SECTION_EFIFW + 1 == _UNIFIED_SECTION_MAX);
                        assert(opt->data < _UNIFIED_SECTION_MAX);

                        r = parse_path_argument(arg, /* suppress_root= */ false, arg_sections + opt->data);
                        if (r < 0)
                                return r;
                        break;
                }

        if (arg_public_key && arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Both --public-key= and --certificate= specified, refusing.");

        if (arg_private_key_source && !arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "When using --private-key-source=, --certificate= must be specified.");

        if (strv_isempty(arg_banks)) {
                /* If no banks are specifically selected, pick all known banks */
                arg_banks = strv_new("SHA1", "SHA256", "SHA384", "SHA512");
                if (!arg_banks)
                        return log_oom();
        }

        strv_sort_uniq(arg_banks);

        if (arg_current)
                for (UnifiedSection us = 0; us < _UNIFIED_SECTION_MAX; us++)
                        if (arg_sections[us])
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "The --current switch cannot be used in combination with --linux= and related switches.");

        if (strv_isempty(arg_phase)) {
                /* If no phases are specifically selected, pick everything from the beginning of the initrd
                 * to the beginning of shutdown. */
                if (strv_extend_many(&arg_phase,
                                     "enter-initrd",
                                     "enter-initrd:leave-initrd",
                                     "enter-initrd:leave-initrd:sysinit",
                                     "enter-initrd:leave-initrd:sysinit:ready") < 0)
                        return log_oom();
        } else
                strv_sort_uniq(arg_phase);

        _cleanup_free_ char *j = NULL;
        j = strv_join(arg_phase, ", ");
        if (!j)
                return log_oom();

        log_debug("Measuring boot phases: %s", j);

        *ret_args = option_parser_get_args(&state);
        return 1;
}

static int compare_reported_pcr_nr(uint32_t pcr, const char *varname, const char *description) {
        _cleanup_free_ char *s = NULL;
        uint32_t v;
        int r;

        r = efi_get_variable_string(varname, &s);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to read EFI variable '%s': %m", varname);

        r = safe_atou32(s, &v);
        if (r < 0)
                return log_error_errno(r, "Failed to parse EFI variable '%s': %s", varname, s);

        if (pcr != v)
                log_warning("PCR number reported by stub for %s (%" PRIu32 ") different from our expectation (%" PRIu32 ").\n"
                            "The measurements are likely inconsistent.", description, v, pcr);

        return 0;
}

static int validate_stub(void) {
        uint64_t features;
        bool found = false;
        int r;

        if (!tpm2_is_fully_supported())
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Sorry, system lacks full TPM2 support.");

        r = efi_stub_get_features(&features);
        if (r < 0)
                return log_error_errno(r, "Unable to get stub features: %m");

        if (!FLAGS_SET(features, EFI_STUB_FEATURE_THREE_PCRS))
                log_warning("Warning: current kernel image does not support measuring itself, the command line or initrd system extension images.\n"
                            "The PCR measurements seen are unlikely to be valid.");

        r = compare_reported_pcr_nr(TPM2_PCR_KERNEL_BOOT, EFI_LOADER_VARIABLE_STR("StubPcrKernelImage"), "kernel image");
        if (r < 0)
                return r;

        STRV_FOREACH(bank, arg_banks) {
                _cleanup_free_ char *b = NULL, *p = NULL;

                b = strdup(*bank);
                if (!b)
                        return log_oom();

                if (asprintf(&p, "/sys/class/tpm/tpm0/pcr-%s/", ascii_strlower(b)) < 0)
                        return log_oom();

                if (access(p, F_OK) < 0) {
                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to detect if '%s' exists: %m", b);
                } else
                        found = true;
        }

        if (!found)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "None of the select PCR banks appear to exist.");

        return 0;
}

VERB(verb_status, "status", NULL, VERB_ANY, 1, VERB_DEFAULT,
     "Show current PCR values");
static int verb_status(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        r = validate_stub();
        if (r < 0)
                return r;

        STRV_FOREACH(bank, arg_banks) {
                _cleanup_free_ char *b = NULL, *p = NULL, *s = NULL;
                _cleanup_free_ void *h = NULL;
                size_t l;

                b = strdup(*bank);
                if (!b)
                        return log_oom();

                if (asprintf(&p, "/sys/class/tpm/tpm0/pcr-%s/%" PRIu32, ascii_strlower(b), (uint32_t) TPM2_PCR_KERNEL_BOOT) < 0)
                        return log_oom();

                r = read_virtual_file(p, 4096, &s, NULL);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to read '%s': %m", p);

                r = unhexmem(strstrip(s), &h, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode PCR value '%s': %m", s);

                if (!sd_json_format_enabled(arg_json_format_flags)) {
                        _cleanup_free_ char *f = hexmem(h, l);
                        if (!f)
                                return log_oom();

                        if (bank == arg_banks) {
                                /* before the first line for each PCR, write a short descriptive text to
                                 * stderr, and leave the primary content on stdout */
                                fflush(stdout);
                                fprintf(stderr, "%s# PCR[%" PRIu32 "] %s%s%s\n",
                                        ansi_grey(),
                                        (uint32_t) TPM2_PCR_KERNEL_BOOT,
                                        tpm2_pcr_index_to_string(TPM2_PCR_KERNEL_BOOT),
                                        memeqzero(h, l) ? " (NOT SET!)" : "",
                                        ansi_normal());
                                fflush(stderr);
                        }

                        printf("%" PRIu32 ":%s=%s\n", (uint32_t) TPM2_PCR_KERNEL_BOOT, b, f);

                } else {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *bv = NULL, *a = NULL;

                        r = sd_json_buildo(
                                        &bv,
                                        SD_JSON_BUILD_PAIR_INTEGER("pcr", TPM2_PCR_KERNEL_BOOT),
                                        SD_JSON_BUILD_PAIR_HEX("hash", h, l));
                        if (r < 0)
                                return log_error_errno(r, "Failed to build JSON object: %m");

                        a = sd_json_variant_ref(sd_json_variant_by_key(v, b));

                        r = sd_json_variant_append_array(&a, bv);
                        if (r < 0)
                                return log_error_errno(r, "Failed to append PCR entry to JSON array: %m");

                        r = sd_json_variant_set_field(&v, b, a);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add bank info to object: %m");
                }
        }

        if (sd_json_format_enabled(arg_json_format_flags)) {
                if (arg_json_format_flags & (SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_PRETTY_AUTO))
                        pager_open(arg_pager_flags);

                sd_json_variant_dump(v, arg_json_format_flags, stdout, NULL);
        }

        return 0;
}

/* The PCR 11 state for one specific bank */
typedef struct PcrState {
        char *bank;
        const EVP_MD *md;
        void *value;
        size_t value_size;
        void *saved_value; /* A copy of the original value we calculated, used by pcr_states_save()/pcr_states_restore() to come later back to */
} PcrState;

static void pcr_state_free_all(PcrState **pcr_state) {
        assert(pcr_state);

        if (!*pcr_state)
                return;

        for (size_t i = 0; (*pcr_state)[i].value; i++) {
                free((*pcr_state)[i].bank);
                free((*pcr_state)[i].value);
                free((*pcr_state)[i].saved_value);
        }

        *pcr_state = mfree(*pcr_state);
}

static void evp_md_ctx_free_all(EVP_MD_CTX **md[]) {
        assert(md);

        if (!*md)
                return;

        for (size_t i = 0; (*md)[i]; i++)
                sym_EVP_MD_CTX_free((*md)[i]);

        *md = mfree(*md);
}

static int pcr_state_extend(PcrState *pcr_state, const void *data, size_t sz) {
        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *mc = NULL;
        unsigned value_size;

        assert(pcr_state);
        assert(data || sz == 0);
        assert(pcr_state->md);
        assert(pcr_state->value);
        assert(pcr_state->value_size > 0);

        /* Extends a (virtual) PCR by the given data */

        mc = sym_EVP_MD_CTX_new();
        if (!mc)
                return log_oom();

        if (sym_EVP_DigestInit_ex(mc, pcr_state->md, NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize %s context.", pcr_state->bank);

        /* First thing we do, is hash the old PCR value */
        if (sym_EVP_DigestUpdate(mc, pcr_state->value, pcr_state->value_size) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to run digest.");

        /* Then, we hash the new data */
        if (sym_EVP_DigestUpdate(mc, data, sz) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to run digest.");

        if (sym_EVP_DigestFinal_ex(mc, pcr_state->value, &value_size) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to finalize hash context.");

        assert(value_size == pcr_state->value_size);
        return 0;
}

#define BUFFER_SIZE (16U * 1024U)

static int measure_kernel(PcrState *pcr_states, size_t n) {
        _cleanup_free_ void *buffer = NULL;
        int r;

        assert(n > 0);
        assert(pcr_states);

        /* Virtually measures the components of a unified kernel image into PCR 11 */

        if (arg_current) {
                /* Shortcut things, if we should just use the current PCR value */

                for (size_t i = 0; i < n; i++) {
                        _cleanup_free_ char *p = NULL, *s = NULL;
                        _cleanup_free_ void *v = NULL;
                        size_t sz;

                        if (asprintf(&p, "/sys/class/tpm/tpm0/pcr-%s/%i", pcr_states[i].bank, TPM2_PCR_KERNEL_BOOT) < 0)
                                return log_oom();

                        r = read_virtual_file(p, 4096, &s, NULL);
                        if (r == -ENOENT && access("/sys/class/tpm/tpm0/", F_OK) >= 0)
                                return log_error_errno(r, "TPM device exists, but cannot open '%s'; either the kernel is too old, or selected PCR bank is not supported: %m", p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read '%s': %m", p);

                        r = unhexmem(strstrip(s), &v, &sz);
                        if (r < 0)
                                return log_error_errno(r, "Failed to decode PCR value '%s': %m", s);

                        assert(pcr_states[i].value_size == sz);
                        memcpy(pcr_states[i].value, v, sz);
                }

                return 0;
        }

        buffer = malloc(BUFFER_SIZE);
        if (!buffer)
                return log_oom();

        for (UnifiedSection c = 0; c < _UNIFIED_SECTION_MAX; c++) {
                _cleanup_(evp_md_ctx_free_all) EVP_MD_CTX **mdctx = NULL;
                _cleanup_close_ int fd = -EBADF;
                uint64_t m = 0;

                if (!arg_sections[c])
                        continue;

                fd = open(arg_sections[c], O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", arg_sections[c]);

                /* Allocate one message digest context per bank (NULL terminated) */
                mdctx = new0(EVP_MD_CTX*, n + 1);
                if (!mdctx)
                        return log_oom();

                for (size_t i = 0; i < n; i++) {
                        mdctx[i] = sym_EVP_MD_CTX_new();
                        if (!mdctx[i])
                                return log_oom();

                        if (sym_EVP_DigestInit_ex(mdctx[i], pcr_states[i].md, NULL) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to initialize data %s context.", pcr_states[i].bank);
                }

                for (;;) {
                        ssize_t sz;

                        sz = read(fd, buffer, BUFFER_SIZE);
                        if (sz < 0)
                                return log_error_errno(errno, "Failed to read '%s': %m", arg_sections[c]);
                        if (sz == 0) /* EOF */
                                break;

                        for (size_t i = 0; i < n; i++)
                                if (sym_EVP_DigestUpdate(mdctx[i], buffer, sz) != 1)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to run digest.");

                        m += sz;
                }

                fd = safe_close(fd);

                if (m == 0) /* We skip over empty files, the stub does so too */
                        continue;

                for (size_t i = 0; i < n; i++) {
                        _cleanup_free_ void *data_hash = NULL;
                        unsigned data_hash_size;

                        data_hash = malloc(pcr_states[i].value_size);
                        if (!data_hash)
                                return log_oom();

                        /* Measure name of section */
                        if (sym_EVP_Digest(unified_sections[c], strlen(unified_sections[c]) + 1, data_hash, &data_hash_size, pcr_states[i].md, NULL) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to hash section name with %s.", pcr_states[i].bank);

                        assert(data_hash_size == (unsigned) pcr_states[i].value_size);

                        r = pcr_state_extend(pcr_states + i, data_hash, data_hash_size);
                        if (r < 0)
                                return r;

                        /* Retrieve hash of data and measure it */
                        if (sym_EVP_DigestFinal_ex(mdctx[i], data_hash, &data_hash_size) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to finalize hash context.");

                        assert(data_hash_size == (unsigned) pcr_states[i].value_size);

                        r = pcr_state_extend(pcr_states + i, data_hash, data_hash_size);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int measure_phase(PcrState *pcr_states, size_t n, const char *phase) {
        _cleanup_strv_free_ char **l = NULL;
        int r;

        assert(pcr_states);
        assert(n > 0);

        /* Measure a phase string into PCR 11. This splits up the "phase" expression at colons, and then
         * virtually extends each specified word into PCR 11, to model how during boot we measure a series of
         * words into PCR 11, one for each phase. */

        l = strv_split(phase, ":");
        if (!l)
                return log_oom();

        STRV_FOREACH(word, l) {
                size_t wl;

                if (isempty(*word))
                        continue;

                wl = strlen(*word);

                for (size_t i = 0; i < n; i++) { /* For each bank */
                        _cleanup_free_ void *b = NULL;
                        int bsz;

                        bsz = sym_EVP_MD_get_size(pcr_states[i].md);
                        assert(bsz > 0);

                        b = malloc(bsz);
                        if (!b)
                                return log_oom();

                        /* First hash the word itself */
                        if (sym_EVP_Digest(*word, wl, b, NULL, pcr_states[i].md, NULL) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to hash word '%s'.", *word);

                        /* And then extend the PCR with the resulting hash */
                        r = pcr_state_extend(pcr_states + i, b, bsz);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int pcr_states_allocate(PcrState **ret) {
        _cleanup_(pcr_state_free_all) PcrState *pcr_states = NULL;
        size_t n = 0;

        assert(ret);

        pcr_states = new0(PcrState, strv_length(arg_banks) + 1);
        if (!pcr_states)
                return log_oom();

        /* Allocate a PCR state structure, one for each bank */
        STRV_FOREACH(d, arg_banks) {
                const EVP_MD *implementation;
                _cleanup_free_ void *v = NULL;
                _cleanup_free_ char *b = NULL;
                int sz;

                assert_se(implementation = sym_EVP_get_digestbyname(*d)); /* Must work, we already checked while parsing  command line */

                b = strdup(sym_EVP_MD_get0_name(implementation));
                if (!b)
                        return log_oom();

                sz = sym_EVP_MD_get_size(implementation);
                if (sz <= 0 || sz >= INT_MAX)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected digest size: %i", sz);

                v = malloc0(sz); /* initial PCR state is all zeroes */
                if (!v)
                        return log_oom();

                pcr_states[n++] = (struct PcrState) {
                        .bank = ascii_strlower(TAKE_PTR(b)),
                        .md = implementation,
                        .value = TAKE_PTR(v),
                        .value_size = sz,
                };
        }

        *ret = TAKE_PTR(pcr_states);
        return (int) n;
}

static int pcr_states_save(PcrState *pcr_states, size_t n) {
        assert(pcr_states);
        assert(n > 0);

        for (size_t i = 0; i < n; i++) {
                _cleanup_free_ void *saved = NULL;

                if (!pcr_states[i].value)
                        continue;

                saved = memdup(pcr_states[i].value, pcr_states[i].value_size);
                if (!saved)
                        return log_oom();

                free_and_replace(pcr_states[i].saved_value, saved);
        }

        return 0;
}

static void pcr_states_restore(PcrState *pcr_states, size_t n) {
        assert(pcr_states);
        assert(n > 0);

        for (size_t i = 0; i < n; i++) {

                assert(pcr_states[i].value);
                assert(pcr_states[i].saved_value);

                memcpy(pcr_states[i].value, pcr_states[i].saved_value, pcr_states[i].value_size);
        }
}

VERB_NOARG(verb_calculate, "calculate",
           "Calculate expected PCR values");
static int verb_calculate(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *w = NULL;
        _cleanup_(pcr_state_free_all) PcrState *pcr_states = NULL;
        int r;

        if (!arg_sections[UNIFIED_SECTION_LINUX] && !arg_current)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Either --linux= or --current must be specified, refusing.");
        if (arg_append)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "The --append= switch is only supported for 'sign', not 'calculate'.");

        assert(!strv_isempty(arg_banks));
        assert(!strv_isempty(arg_phase));

        r = pcr_states_allocate(&pcr_states);
        if (r < 0)
                return r;

        size_t n = r;

        r = measure_kernel(pcr_states, n);
        if (r < 0)
                return r;

        /* Save the current state, so that we later can restore to it. This way we can measure the PCR values
         * for multiple different boot phases without heaving to start from zero each time */
        r = pcr_states_save(pcr_states, n);
        if (r < 0)
                return r;

        STRV_FOREACH(phase, arg_phase) {

                r = measure_phase(pcr_states, n, *phase);
                if (r < 0)
                        return r;

                for (size_t i = 0; i < n; i++) {
                        if (!sd_json_format_enabled(arg_json_format_flags)) {
                                _cleanup_free_ char *hd = NULL;

                                if (i == 0) {
                                        fflush(stdout);
                                        fprintf(stderr, "%s# PCR[%i] Phase <%s>%s\n",
                                                ansi_grey(),
                                                TPM2_PCR_KERNEL_BOOT,
                                                isempty(*phase) ? ":" : *phase,
                                                ansi_normal());
                                        fflush(stderr);
                                }

                                hd = hexmem(pcr_states[i].value, pcr_states[i].value_size);
                                if (!hd)
                                        return log_oom();

                                printf("%i:%s=%s\n", TPM2_PCR_KERNEL_BOOT, pcr_states[i].bank, hd);
                        } else {
                                _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;

                                array = sd_json_variant_ref(sd_json_variant_by_key(w, pcr_states[i].bank));

                                r = sd_json_variant_append_arraybo(
                                                &array,
                                                SD_JSON_BUILD_PAIR_CONDITION(!isempty(*phase), "phase", SD_JSON_BUILD_STRING(*phase)),
                                                SD_JSON_BUILD_PAIR_INTEGER("pcr", TPM2_PCR_KERNEL_BOOT),
                                                SD_JSON_BUILD_PAIR_HEX("hash", pcr_states[i].value, pcr_states[i].value_size));
                                if (r < 0)
                                        return log_error_errno(r, "Failed to append JSON object to array: %m");

                                r = sd_json_variant_set_field(&w, pcr_states[i].bank, array);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to add bank info to object: %m");
                        }
                }

                /* Return to the original kernel measurement for the next phase calculation */
                pcr_states_restore(pcr_states, n);
        }

        if (sd_json_format_enabled(arg_json_format_flags)) {

                if (arg_json_format_flags & (SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_PRETTY_AUTO))
                        pager_open(arg_pager_flags);

                sd_json_variant_dump(w, arg_json_format_flags, stdout, NULL);
        }

        return 0;
}

static int build_policy_digest(bool sign) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(pcr_state_free_all) PcrState *pcr_states = NULL;
        _cleanup_(openssl_ask_password_ui_freep) OpenSSLAskPasswordUI *ui = NULL;
        _cleanup_(EVP_PKEY_freep) EVP_PKEY *privkey = NULL, *pubkey = NULL;
        _cleanup_(X509_freep) X509 *certificate = NULL;
        size_t n;
        int r;

        if (!arg_sections[UNIFIED_SECTION_LINUX] && !arg_current)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Either --linux= or --current must be specified, refusing.");

        if (sign && !arg_private_key)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "No private key specified, use --private-key=.");

        assert(!strv_isempty(arg_banks));
        assert(!strv_isempty(arg_phase));

        if (arg_append) {
                r = sd_json_parse_file(/* f= */ NULL, arg_append, SD_JSON_PARSE_MUST_BE_OBJECT, &v, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse JSON object '%s': %m", arg_append);
        }

        /* When signing/building digest we only support JSON output */
        arg_json_format_flags &= ~SD_JSON_FORMAT_OFF;

        /* This must be done before openssl_load_private_key() otherwise it will get stuck */
        if (arg_certificate) {
                if (arg_certificate_source_type == OPENSSL_CERTIFICATE_SOURCE_FILE) {
                        r = parse_path_argument(arg_certificate, /* suppress_root= */ false, &arg_certificate);
                        if (r < 0)
                                return r;
                }

                r = openssl_load_x509_certificate(
                                arg_certificate_source_type,
                                arg_certificate_source,
                                arg_certificate,
                                &certificate);
                if (r < 0)
                        return log_error_errno(r, "Failed to load X.509 certificate from %s: %m", arg_certificate);
        }

        if (arg_private_key) {
                if (arg_private_key_source_type == OPENSSL_KEY_SOURCE_FILE) {
                        r = parse_path_argument(arg_private_key, /* suppress_root= */ false, &arg_private_key);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse private key path %s: %m", arg_private_key);
                }

                r = openssl_load_private_key(
                                arg_private_key_source_type,
                                arg_private_key_source,
                                arg_private_key,
                                &(AskPasswordRequest) {
                                        .tty_fd = -EBADF,
                                        .id = "measure-private-key-pin",
                                        .keyring = arg_private_key,
                                        .credential = "measure.private-key-pin",
                                        .until = USEC_INFINITY,
                                        .hup_fd = -EBADF,
                                },
                                &privkey,
                                &ui);
                if (r < 0)
                        return log_error_errno(r, "Failed to load private key from %s: %m", arg_private_key);
        }

        if (arg_public_key) {
                _cleanup_fclose_ FILE *pubkeyf = NULL;

                pubkeyf = fopen(arg_public_key, "re");
                if (!pubkeyf)
                        return log_error_errno(errno, "Failed to open public key file '%s': %m", arg_public_key);

                pubkey = sym_PEM_read_PUBKEY(pubkeyf, NULL, NULL, NULL);
                if (!pubkey)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to parse public key '%s'.", arg_public_key);
        } else if (certificate) {
                pubkey = sym_X509_get_pubkey(certificate);
                if (!pubkey)
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(EIO),
                                        "Failed to extract public key from certificate %s.",
                                        arg_certificate);
        } else if (sign) {
                /* No public key was specified, let's derive it automatically, if we can, when signing */
                r = openssl_extract_public_key(privkey, &pubkey);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract public key from private key file '%s': %m", arg_private_key);
        }

        r = pcr_states_allocate(&pcr_states);
        if (r < 0)
                return r;

        n = (size_t) r;

        r = measure_kernel(pcr_states, n);
        if (r < 0)
                return r;

        r = pcr_states_save(pcr_states, n);
        if (r < 0)
                return r;

        STRV_FOREACH(phase, arg_phase) {

                r = measure_phase(pcr_states, n, *phase);
                if (r < 0)
                        return r;

                for (size_t i = 0; i < n; i++) {
                        PcrState *p = pcr_states + i;

                        int tpmalg = tpm2_hash_alg_from_string(sym_EVP_MD_get0_name(p->md));
                        if (tpmalg < 0)
                                return log_error_errno(tpmalg, "Unsupported PCR bank");

                        Tpm2PCRValue pcr_value = TPM2_PCR_VALUE_MAKE(TPM2_PCR_KERNEL_BOOT,
                                                                     tpmalg,
                                                                     TPM2B_DIGEST_MAKE(p->value, p->value_size));

                        TPM2B_DIGEST pcr_policy_digest = TPM2B_DIGEST_MAKE(NULL, TPM2_SHA256_DIGEST_SIZE);

                        r = tpm2_calculate_policy_pcr(&pcr_value, 1, &pcr_policy_digest);
                        if (r < 0)
                                return log_error_errno(r, "Could not calculate PolicyPCR digest: %m");

                        _cleanup_free_ void *sig = NULL;
                        size_t ss = 0;
                        if (privkey) {
                                /* We always use SHA256 for signing currently. Regardless of the bank. */
                                const EVP_MD *sha256 = ASSERT_PTR(sym_EVP_get_digestbyname("sha256"));

                                r = digest_and_sign(sha256, privkey, pcr_policy_digest.buffer, pcr_policy_digest.size, &sig, &ss);
                                if (r == -EADDRNOTAVAIL)
                                        return log_error_errno(r, "Hash algorithm '%s' not available while signing. (Maybe OS security policy disables this algorithm?)", sym_EVP_MD_get0_name(p->md));
                                if (r < 0)
                                        return log_error_errno(r, "Failed to sign PCR policy with hash algorithm '%s': %m", sym_EVP_MD_get0_name(p->md));
                        }

                        _cleanup_free_ void *pubkey_fp = NULL;
                        size_t pubkey_fp_size = 0;
                        if (pubkey) {
                                r = pubkey_fingerprint(pubkey, sym_EVP_sha256(), &pubkey_fp, &pubkey_fp_size);
                                if (r < 0)
                                        return r;
                        }

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL;
                        r = tpm2_make_pcr_json_array(UINT64_C(1) << TPM2_PCR_KERNEL_BOOT, &a);
                        if (r < 0)
                                return log_error_errno(r, "Failed to build JSON PCR mask array: %m");

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *bv = NULL;
                        r = sd_json_buildo(&bv,
                                           SD_JSON_BUILD_PAIR_VARIANT("pcrs", a),                                                   /* PCR mask */
                                           SD_JSON_BUILD_PAIR_CONDITION(pubkey_fp_size > 0, "pkfp", SD_JSON_BUILD_HEX(pubkey_fp, pubkey_fp_size)), /* SHA256 fingerprint of public key (DER) used for the signature */
                                           SD_JSON_BUILD_PAIR_HEX("pol", pcr_policy_digest.buffer, pcr_policy_digest.size),         /* TPM2 policy hash that is signed */
                                           SD_JSON_BUILD_PAIR_CONDITION(ss > 0, "sig", SD_JSON_BUILD_BASE64(sig, ss)));                            /* signature data */
                        if (r < 0)
                                return log_error_errno(r, "Failed to build JSON object: %m");

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *av = NULL;
                        av = sd_json_variant_ref(sd_json_variant_by_key(v, p->bank));

                        r = sd_json_variant_append_array_nodup(&av, bv);
                        if (r < 0)
                                return log_error_errno(r, "Failed to append JSON object: %m");

                        r = sd_json_variant_set_field(&v, p->bank, av);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add JSON field: %m");
                }

                /* Return to the original kernel measurement for the next phase calculation */
                pcr_states_restore(pcr_states, n);
        }

        if (arg_json_format_flags & (SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_PRETTY_AUTO))
                pager_open(arg_pager_flags);

        sd_json_variant_dump(v, arg_json_format_flags, stdout, NULL);

        return 0;
}

VERB_NOARG(verb_sign, "sign",
           "Calculate and sign expected PCR values");
static int verb_sign(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return build_policy_digest(/* sign= */ true);
}

VERB_NOARG(verb_policy_digest, "policy-digest",
           "Calculate expected TPM2 policy digests");
static int verb_policy_digest(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return build_policy_digest(/* sign= */ false);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

        return dispatch_verb_with_args(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
