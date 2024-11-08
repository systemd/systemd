/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "ask-password-api.h"
#include "build.h"
#include "efi-loader.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "main-func.h"
#include "memstream-util.h"
#include "openssl-util.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pe-binary.h"
#include "pretty-print.h"
#include "sha256.h"
#include "strv.h"
#include "terminal-util.h"
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

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-measure", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s  [OPTIONS...] COMMAND ...\n"
               "\n%5$sPre-calculate and sign PCR hash for a unified kernel image (UKI).%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  status                 Show current PCR values\n"
               "  calculate              Calculate expected PCR values\n"
               "  sign                   Calculate and sign expected PCR values\n"
               "  policy-digest          Calculate expected TPM2 policy digests\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help              Show this help\n"
               "     --version           Print version\n"
               "     --no-pager          Do not pipe output into a pager\n"
               "  -c --current           Use current PCR values\n"
               "     --phase=PHASE       Specify a boot phase to sign for\n"
               "     --bank=DIGEST       Select TPM bank (SHA1, SHA256, SHA384, SHA512)\n"
               "     --tpm2-device=PATH  Use specified TPM2 device\n"
               "     --private-key=KEY   Private key (PEM) to sign with\n"
               "     --private-key-source=file|provider:PROVIDER|engine:ENGINE\n"
               "                         Specify how to use KEY for --private-key=. Allows\n"
               "                         an OpenSSL engine/provider to be used for signing\n"
               "     --public-key=KEY    Public key (PEM) to validate against\n"
               "     --certificate=PATH|URI\n"
               "                         PEM certificate to use for signing, or a provider\n"
               "                         specific designation if --certificate-source= is used\n"
               "     --certificate-source=file|provider:PROVIDER\n"
               "                         Specify how to interpret the certificate from\n"
               "                         --certificate=. Allows the certificate to be loaded\n"
               "                         from an OpenSSL provider\n"
               "     --json=MODE         Output as JSON\n"
               "  -j                     Same as --json=pretty on tty, --json=short otherwise\n"
               "     --append=PATH       Load specified JSON signature, and append new signature to it\n"
               "\n%3$sUKI PE Section Options:%4$s                                         %3$sUKI PE Section%4$s\n"
               "     --linux=PATH        Path to Linux kernel image file            %7$s .linux\n"
               "     --osrel=PATH        Path to os-release file                    %7$s .osrel\n"
               "     --cmdline=PATH      Path to file with kernel command line      %7$s .cmdline\n"
               "     --initrd=PATH       Path to initrd image file                  %7$s .initrd\n"
               "     --ucode=PATH        Path to microcode image file               %7$s .ucode\n"
               "     --splash=PATH       Path to splash bitmap file                 %7$s .splash\n"
               "     --dtb=PATH          Path to DeviceTree file                    %7$s .dtb\n"
               "     --dtbauto=PATH      Path to DeviceTree file for auto selection %7$s .dtbauto\n"
               "     --uname=PATH        Path to 'uname -r' file                    %7$s .uname\n"
               "     --sbat=PATH         Path to SBAT file                          %7$s .sbat\n"
               "     --pcrpkey=PATH      Path to public key for PCR signatures      %7$s .pcrpkey\n"
               "     --profile=PATH      Path to profile file                       %7$s .profile\n"
               "     --hwids=PATH        Path to HWIDs file                         %7$s .hwids\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal(),
               special_glyph(SPECIAL_GLYPH_ARROW_RIGHT));

        return 0;
}

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

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                _ARG_SECTION_FIRST,
                ARG_LINUX = _ARG_SECTION_FIRST,
                ARG_OSREL,
                ARG_CMDLINE,
                ARG_INITRD,
                ARG_UCODE,
                ARG_SPLASH,
                ARG_DTB,
                ARG_UNAME,
                ARG_SBAT,
                _ARG_PCRSIG, /* the .pcrsig section is not input for signing, hence not actually an argument here */
                ARG_PCRPKEY,
                ARG_PROFILE,
                ARG_DTBAUTO,
                ARG_HWIDS,
                _ARG_SECTION_LAST,
                ARG_EFIFW = _ARG_SECTION_LAST,
                ARG_BANK,
                ARG_PRIVATE_KEY,
                ARG_PRIVATE_KEY_SOURCE,
                ARG_PUBLIC_KEY,
                ARG_CERTIFICATE,
                ARG_CERTIFICATE_SOURCE,
                ARG_TPM2_DEVICE,
                ARG_JSON,
                ARG_PHASE,
                ARG_APPEND,
        };

        static const struct option options[] = {
                { "help",               no_argument,       NULL, 'h'                    },
                { "no-pager",           no_argument,       NULL, ARG_NO_PAGER           },
                { "version",            no_argument,       NULL, ARG_VERSION            },
                { "linux",              required_argument, NULL, ARG_LINUX              },
                { "osrel",              required_argument, NULL, ARG_OSREL              },
                { "cmdline",            required_argument, NULL, ARG_CMDLINE            },
                { "initrd",             required_argument, NULL, ARG_INITRD             },
                { "ucode",              required_argument, NULL, ARG_UCODE              },
                { "splash",             required_argument, NULL, ARG_SPLASH             },
                { "dtb",                required_argument, NULL, ARG_DTB                },
                { "dtbauto",            required_argument, NULL, ARG_DTBAUTO            },
                { "uname",              required_argument, NULL, ARG_UNAME              },
                { "sbat",               required_argument, NULL, ARG_SBAT               },
                { "pcrpkey",            required_argument, NULL, ARG_PCRPKEY            },
                { "profile",            required_argument, NULL, ARG_PROFILE            },
                { "hwids",              required_argument, NULL, ARG_HWIDS              },
                { "current",            no_argument,       NULL, 'c'                    },
                { "bank",               required_argument, NULL, ARG_BANK               },
                { "tpm2-device",        required_argument, NULL, ARG_TPM2_DEVICE        },
                { "private-key",        required_argument, NULL, ARG_PRIVATE_KEY        },
                { "private-key-source", required_argument, NULL, ARG_PRIVATE_KEY_SOURCE },
                { "public-key",         required_argument, NULL, ARG_PUBLIC_KEY         },
                { "certificate",        required_argument, NULL, ARG_CERTIFICATE        },
                { "certificate-source", required_argument, NULL, ARG_CERTIFICATE_SOURCE },
                { "json",               required_argument, NULL, ARG_JSON               },
                { "phase",              required_argument, NULL, ARG_PHASE              },
                { "append",             required_argument, NULL, ARG_APPEND             },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        /* Make sure the arguments list and the section list, stays in sync */
        assert_cc(_ARG_SECTION_FIRST + _UNIFIED_SECTION_MAX == _ARG_SECTION_LAST + 1);

        while ((c = getopt_long(argc, argv, "hjc", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help(0, NULL, NULL);
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case _ARG_SECTION_FIRST..._ARG_SECTION_LAST: {
                        UnifiedSection section = c - _ARG_SECTION_FIRST;

                        r = parse_path_argument(optarg, /* suppress_root= */ false, arg_sections + section);
                        if (r < 0)
                                return r;
                        break;
                }

                case 'c':
                        arg_current = true;
                        break;

                case ARG_BANK: {
                        const EVP_MD *implementation;

                        implementation = EVP_get_digestbyname(optarg);
                        if (!implementation)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown bank '%s', refusing.", optarg);

                        if (strv_extend(&arg_banks, EVP_MD_name(implementation)) < 0)
                                return log_oom();

                        break;
                }

                case ARG_PRIVATE_KEY:
                        r = free_and_strdup_warn(&arg_private_key, optarg);
                        if (r < 0)
                                return r;

                        break;

                case ARG_PRIVATE_KEY_SOURCE:
                        r = parse_openssl_key_source_argument(
                                        optarg,
                                        &arg_private_key_source,
                                        &arg_private_key_source_type);
                        if (r < 0)
                                return r;

                        break;

                case ARG_PUBLIC_KEY:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_public_key);
                        if (r < 0)
                                return r;

                        break;

                case ARG_CERTIFICATE:
                        r = free_and_strdup_warn(&arg_certificate, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_CERTIFICATE_SOURCE:
                        r = parse_openssl_certificate_source_argument(
                                        optarg,
                                        &arg_certificate_source,
                                        &arg_certificate_source_type);
                        if (r < 0)
                                return r;
                        break;

                case ARG_TPM2_DEVICE: {
                        _cleanup_free_ char *device = NULL;

                        if (streq(optarg, "list"))
                                return tpm2_list_devices(/* legend = */ true, /* quiet = */ false);

                        if (!streq(optarg, "auto")) {
                                device = strdup(optarg);
                                if (!device)
                                        return log_oom();
                        }

                        free_and_replace(arg_tpm2_device, device);
                        break;
                }

                case 'j':
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case ARG_PHASE: {
                        char *n;

                        n = normalize_phase(optarg);
                        if (!n)
                                return log_oom();

                        r = strv_consume(&arg_phase, TAKE_PTR(n));
                        if (r < 0)
                                return r;

                        break;
                }

                case ARG_APPEND:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_append);
                        if (r < 0)
                                return r;

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
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
        return 1;
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
                EVP_MD_CTX_free((*md)[i]);

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

        mc = EVP_MD_CTX_new();
        if (!mc)
                return log_oom();

        if (EVP_DigestInit_ex(mc, pcr_state->md, NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize %s context.", pcr_state->bank);

        /* First thing we do, is hash the old PCR value */
        if (EVP_DigestUpdate(mc, pcr_state->value, pcr_state->value_size) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to run digest.");

        /* Then, we hash the new data */
        if (EVP_DigestUpdate(mc, data, sz) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to run digest.");

        if (EVP_DigestFinal_ex(mc, pcr_state->value, &value_size) != 1)
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
                        mdctx[i] = EVP_MD_CTX_new();
                        if (!mdctx[i])
                                return log_oom();

                        if (EVP_DigestInit_ex(mdctx[i], pcr_states[i].md, NULL) != 1)
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
                                if (EVP_DigestUpdate(mdctx[i], buffer, sz) != 1)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to run digest.");

                        m += sz;
                }

                if (c == UNIFIED_SECTION_LINUX) {
                        _cleanup_free_ PeHeader *pe_header = NULL;

                        r = pe_load_headers(fd, /*ret_dos_header=*/ NULL, &pe_header);
                        if (r < 0)
                                log_warning_errno(r, "Failed to parse kernel image file '%s', ignoring: %m", arg_sections[c]);
                        else if (m < pe_header->optional.SizeOfImage) {
                                memzero(buffer, BUFFER_SIZE);

                                /* Our EFI stub measures VirtualSize bytes of the .linux section into PCR 11.
                                 * Notably, VirtualSize can be larger than the section's size on disk. In
                                 * that case the extra space is initialized with zeros, so the stub ends up
                                 * measuring a bunch of zeros. To accommodate this, we have to measure the
                                 * same number of zeros here. We opt to measure extra zeros here instead of
                                 * modifying the stub to only measure the number of bytes on disk as we want
                                 * newer ukify + systemd-measure to work with older versions of the stub and
                                 * as of 6.12 the kernel image's VirtualSize won't be larger than its size on
                                 * disk anymore (see https://github.com/systemd/systemd/issues/34578#issuecomment-2382459515).
                                 */

                                while (m < pe_header->optional.SizeOfImage) {
                                        uint64_t sz = MIN(BUFFER_SIZE, pe_header->optional.SizeOfImage - m);

                                        for (size_t i = 0; i < n; i++)
                                                if (EVP_DigestUpdate(mdctx[i], buffer, sz) != 1)
                                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to run digest.");

                                        m += sz;
                                }
                        }
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
                        if (EVP_Digest(unified_sections[c], strlen(unified_sections[c]) + 1, data_hash, &data_hash_size, pcr_states[i].md, NULL) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to hash section name with %s.", pcr_states[i].bank);

                        assert(data_hash_size == (unsigned) pcr_states[i].value_size);

                        r = pcr_state_extend(pcr_states + i, data_hash, data_hash_size);
                        if (r < 0)
                                return r;

                        /* Retrieve hash of data and measure it */
                        if (EVP_DigestFinal_ex(mdctx[i], data_hash, &data_hash_size) != 1)
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

                        bsz = EVP_MD_size(pcr_states[i].md);
                        assert(bsz > 0);

                        b = malloc(bsz);
                        if (!b)
                                return log_oom();

                        /* First hash the word itself */
                        if (EVP_Digest(*word, wl, b, NULL, pcr_states[i].md, NULL) != 1)
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

        pcr_states = new0(PcrState, strv_length(arg_banks) + 1);
        if (!pcr_states)
                return log_oom();

        /* Allocate a PCR state structure, one for each bank */
        STRV_FOREACH(d, arg_banks) {
                const EVP_MD *implementation;
                _cleanup_free_ void *v = NULL;
                _cleanup_free_ char *b = NULL;
                int sz;

                assert_se(implementation = EVP_get_digestbyname(*d)); /* Must work, we already checked while parsing  command line */

                b = strdup(EVP_MD_name(implementation));
                if (!b)
                        return log_oom();

                sz = EVP_MD_size(implementation);
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

static int verb_calculate(int argc, char *argv[], void *userdata) {
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
                                                SD_JSON_BUILD_PAIR("pcr", SD_JSON_BUILD_INTEGER(TPM2_PCR_KERNEL_BOOT)),
                                                SD_JSON_BUILD_PAIR("hash", SD_JSON_BUILD_HEX(pcr_states[i].value, pcr_states[i].value_size)));
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
                r = sd_json_parse_file(NULL, arg_append, 0, &v, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse '%s': %m", arg_append);

                if (!sd_json_variant_is_object(v))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "File '%s' is not a valid JSON object, refusing.", arg_append);
        }

        /* When signing/building digest we only support JSON output */
        arg_json_format_flags &= ~SD_JSON_FORMAT_OFF;

        /* This must be done before openssl_load_private_key() otherwise it will get stuck */
        if (arg_certificate) {
                if (arg_certificate_source_type == OPENSSL_CERTIFICATE_SOURCE_FILE) {
                        r = parse_path_argument(arg_certificate, /*suppress_root=*/ false, &arg_certificate);
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

                pubkey = PEM_read_PUBKEY(pubkeyf, NULL, NULL, NULL);
                if (!pubkey)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to parse public key '%s'.", arg_public_key);
        } else if (certificate) {
                pubkey = X509_get_pubkey(certificate);
                if (!pubkey)
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(EIO),
                                        "Failed to extract public key from certificate %s.",
                                        arg_certificate);
        } else if (sign) {
                _cleanup_(memstream_done) MemStream m = {};
                FILE *tf;

                /* No public key was specified, let's derive it automatically, if we can, when signing */

                tf = memstream_init(&m);
                if (!tf)
                        return log_oom();

                if (i2d_PUBKEY_fp(tf, privkey) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to extract public key from private key file '%s'.", arg_private_key);

                fflush(tf);
                rewind(tf);

                if (!d2i_PUBKEY_fp(tf, &pubkey))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to parse extracted public key of private key file '%s'.", arg_private_key);
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

                        int tpmalg = tpm2_hash_alg_from_string(EVP_MD_name(p->md));
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
                                r = digest_and_sign(p->md, privkey, pcr_policy_digest.buffer, pcr_policy_digest.size, &sig, &ss);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to sign PCR policy: %m");
                        }

                        _cleanup_free_ void *pubkey_fp = NULL;
                        size_t pubkey_fp_size = 0;
                        if (pubkey) {
                                r = pubkey_fingerprint(pubkey, EVP_sha256(), &pubkey_fp, &pubkey_fp_size);
                                if (r < 0)
                                        return r;
                        }

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *a = NULL;
                        r = tpm2_make_pcr_json_array(UINT64_C(1) << TPM2_PCR_KERNEL_BOOT, &a);
                        if (r < 0)
                                return log_error_errno(r, "Failed to build JSON PCR mask array: %m");

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *bv = NULL;
                        r = sd_json_buildo(&bv,
                                           SD_JSON_BUILD_PAIR("pcrs", SD_JSON_BUILD_VARIANT(a)),                                                   /* PCR mask */
                                           SD_JSON_BUILD_PAIR_CONDITION(pubkey_fp_size > 0, "pkfp", SD_JSON_BUILD_HEX(pubkey_fp, pubkey_fp_size)), /* SHA256 fingerprint of public key (DER) used for the signature */
                                           SD_JSON_BUILD_PAIR("pol", SD_JSON_BUILD_HEX(pcr_policy_digest.buffer, pcr_policy_digest.size)),         /* TPM2 policy hash that is signed */
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

static int verb_sign(int argc, char *argv[], void *userdata) {
        return build_policy_digest(/* sign= */ true);
}

static int verb_policy_digest(int argc, char *argv[], void *userdata) {
        return build_policy_digest(/* sign= */ false);
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

static int verb_status(int argc, char *argv[], void *userdata) {
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
                        _cleanup_free_ char *f = NULL;

                        f = hexmem(h, l);
                        if (!h)
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
                                        SD_JSON_BUILD_PAIR("pcr", SD_JSON_BUILD_INTEGER(TPM2_PCR_KERNEL_BOOT)),
                                        SD_JSON_BUILD_PAIR("hash", SD_JSON_BUILD_HEX(h, l)));
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

static int measure_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",          VERB_ANY, VERB_ANY, 0,            help               },
                { "status",        VERB_ANY, 1,        VERB_DEFAULT, verb_status        },
                { "calculate",     VERB_ANY, 1,        0,            verb_calculate     },
                { "policy-digest", VERB_ANY, 1,        0,            verb_policy_digest },
                { "sign",          VERB_ANY, 1,        0,            verb_sign          },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return measure_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
