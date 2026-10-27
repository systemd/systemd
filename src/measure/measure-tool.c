/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "ansi-color.h"
#include "ask-password-api.h"
#include "build.h"
#include "crypto-util.h"
#include "dlopen-note.h"
#include "efi-loader.h"
#include "efivars.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "log.h"
#include "main-func.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "predict-measure.h"
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
static char *arg_policyref = NULL;
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
STATIC_DESTRUCTOR_REGISTER(arg_policyref, freep);
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

COMMAND(
        "systemd-measure\0",
        "Pre-calculate and sign PCR hash for a unified kernel image (UKI).",
        .man_pages = "systemd-measure(1)\0",
        .pager_flags = &arg_pager_flags,
        .flags = COMMAND_EXPERIMENTAL,
);

VERB_COMMON_HELP_AUTO_HIDDEN();

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };
        int r;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return command_print_help();

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
                            "Specify a boot phase to sign for"):
                        if (strv_extend(&arg_phase, opts.arg) < 0)
                                return log_oom();

                        break;

                OPTION_LONG("bank", "DIGEST",
                            "Select TPM bank (SHA1, SHA256, SHA384, SHA512)"): {
                        const EVP_MD *implementation;

                        r = dlopen_libcrypto(LOG_ERR);
                        if (r < 0)
                                return r;

                        implementation = sym_EVP_get_digestbyname(opts.arg);
                        if (!implementation)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown bank '%s', refusing.", opts.arg);

                        if (strv_extend(&arg_banks, sym_EVP_MD_get0_name(implementation)) < 0)
                                return log_oom();

                        break;
                }

                OPTION_LONG("tpm2-device", "PATH",
                            "Use specified TPM2 device"): {
                        _cleanup_free_ char *device = NULL;

                        if (streq(opts.arg, "list"))
                                return tpm2_list_devices(/* legend= */ true, /* quiet= */ false);

                        if (!streq(opts.arg, "auto")) {
                                device = strdup(opts.arg);
                                if (!device)
                                        return log_oom();
                        }

                        free_and_replace(arg_tpm2_device, device);
                        break;
                }

                OPTION_LONG("policyref", "STRING",
                            "Set a policyref and include this in the signatures"):
                        r = free_and_strdup_warn(&arg_policyref, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_PRIVATE_KEY("Private key (PEM) to sign with"):
                        r = free_and_strdup_warn(&arg_private_key, opts.arg);
                        if (r < 0)
                                return r;

                        break;

                OPTION_COMMON_PRIVATE_KEY_SOURCE:
                        r = parse_openssl_key_source_argument(
                                        opts.arg,
                                        &arg_private_key_source,
                                        &arg_private_key_source_type);
                        if (r < 0)
                                return r;

                        break;

                OPTION_LONG("public-key", "KEY",
                            "Public key (PEM) to validate against"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_public_key);
                        if (r < 0)
                                return r;

                        break;

                OPTION_COMMON_CERTIFICATE("PEM certificate to use for signing"):
                        r = free_and_strdup_warn(&arg_certificate, opts.arg);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_CERTIFICATE_SOURCE:
                        r = parse_openssl_certificate_source_argument(
                                        opts.arg,
                                        &arg_certificate_source,
                                        &arg_certificate_source_type);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                OPTION_COMMON_LOWERCASE_J:
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                OPTION_LONG("append", "PATH",
                            "Load specified JSON signature, and append new signature to it"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_append);
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
                        assert(opts.opt->data < _UNIFIED_SECTION_MAX);

                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, arg_sections + opts.opt->data);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(arg_json_format_flags);
                }

        if (arg_public_key && arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Both --public-key= and --certificate= specified, refusing.");

        if (arg_private_key_source && !arg_certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "When using --private-key-source=, --certificate= must be specified.");

        char **banks = NULL;
        r = measure_normalize_banks(arg_banks, &banks);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PCR banks: %m");

        strv_free_and_replace(arg_banks, banks);

        if (arg_current)
                for (UnifiedSection us = 0; us < _UNIFIED_SECTION_MAX; us++)
                        if (arg_sections[us])
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "The --current switch cannot be used in combination with --linux= and related switches.");

        char **phases = NULL;
        r = measure_normalize_phases(arg_phase, &phases);
        if (r < 0)
                return log_error_errno(r, "Failed to parse boot phases: %m");

        strv_free_and_replace(arg_phase, phases);

        _cleanup_free_ char *j = NULL;
        j = strv_join(arg_phase, ", ");
        if (!j)
                return log_oom();

        log_debug("Measuring boot phases: %s", j);

        *ret_args = option_parser_get_args(&opts);
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

VERB_DEFAULT_NOARG(verb_status, "status", "Show current PCR values");
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

static int measure_kernel(PcrState *pcr_states, size_t n) {
        int section_fds[_UNIFIED_SECTION_MAX];
        int r;

        assert(n > 0);
        assert(pcr_states);

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

        for (UnifiedSection c = 0; c < _UNIFIED_SECTION_MAX; c++) {
                section_fds[c] = -EBADF;

                if (!arg_sections[c])
                        continue;

                section_fds[c] = open(arg_sections[c], O_RDONLY|O_CLOEXEC);
                if (section_fds[c] < 0) {
                        r = log_error_errno(errno, "Failed to open '%s': %m", arg_sections[c]);
                        close_many(section_fds, c);
                        return r;
                }
        }

        r = pcr_states_measure_uki(pcr_states, n, section_fds);
        close_many(section_fds, _UNIFIED_SECTION_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to measure UKI sections: %m");

        return 0;
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

        r = pcr_states_allocate(arg_banks, &pcr_states);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate PCR states: %m");

        size_t n = r;

        r = measure_kernel(pcr_states, n);
        if (r < 0)
                return r;

        r = measure_calculate(pcr_states, n, arg_phase, &w);
        if (r < 0)
                return log_error_errno(r, "Failed to calculate PCR values: %m");

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                measure_calculate_print(w);
                return 0;
        }

        if (arg_json_format_flags & (SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_PRETTY_AUTO))
                pager_open(arg_pager_flags);

        sd_json_variant_dump(w, arg_json_format_flags, stdout, NULL);
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
                                return r;
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

        r = pcr_states_allocate(arg_banks, &pcr_states);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate PCR states: %m");

        n = (size_t) r;

        r = measure_kernel(pcr_states, n);
        if (r < 0)
                return r;

        r = measure_build_policy(pcr_states, n, arg_phase, privkey, pubkey, arg_policyref, /* include_tbs= */ !sign, &v);
        if (r == -EADDRNOTAVAIL)
                return log_error_errno(r, "Hash algorithm 'SHA256' not available while signing. (Maybe OS security policy disables this algorithm?)");
        if (r < 0)
                return log_error_errno(r, "Failed to build PCR policy: %m");

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

        LIBCRYPTO_NOTE(required);
        TPM2_NOTE(suggested);

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        r = dlopen_libcrypto(LOG_ERR);
        if (r < 0)
                return r;

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
