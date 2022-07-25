/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "alloc-util.h"
#include "efi-loader.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "main-func.h"
#include "openssl-util.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "terminal-util.h"
#include "tpm-pcr.h"
#include "tpm2-util.h"
#include "verbs.h"

/* Tool for pre-calculating expected TPM PCR values based on measured resources. This is intended to be used
 * to pre-calculate suitable values for PCR 11, the way sd-stub measures into it. */

static char *arg_sections[_UNIFIED_SECTION_MAX] = {};
static char **arg_banks = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_banks, strv_freep);

static inline void free_sections(char*(*sections)[_UNIFIED_SECTION_MAX]) {
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
               "\n%5$sPre-calculate PCR hash for kernel image.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  status             Show current PCR values\n"
               "  calculate          Calculate expected PCR values\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help          Show this help\n"
               "     --version       Print version\n"
               "     --linux=PATH    Path Linux kernel ELF image\n"
               "     --osrel=PATH    Path to os-release file\n"
               "     --cmdline=PATH  Path to file with kernel command line\n"
               "     --initrd=PATH   Path to initrd image\n"
               "     --splash=PATH   Path to splash bitmap\n"
               "     --dtb=PATH      Path to Devicetree file\n"
               "     --bank=DIGEST   Select TPM bank (SHA1, SHA256)\n"
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
                _ARG_SECTION_FIRST,
                ARG_LINUX = _ARG_SECTION_FIRST,
                ARG_OSREL,
                ARG_CMDLINE,
                ARG_INITRD,
                ARG_SPLASH,
                _ARG_SECTION_LAST,
                ARG_DTB = _ARG_SECTION_LAST,
                ARG_BANK,
        };

        static const struct option options[] = {
                { "help",    no_argument,       NULL, 'h'         },
                { "version", no_argument,       NULL, ARG_VERSION },
                { "linux",   required_argument, NULL, ARG_LINUX   },
                { "osrel",   required_argument, NULL, ARG_OSREL   },
                { "cmdline", required_argument, NULL, ARG_CMDLINE },
                { "initrd",  required_argument, NULL, ARG_INITRD  },
                { "splash",  required_argument, NULL, ARG_SPLASH  },
                { "dtb",     required_argument, NULL, ARG_DTB     },
                { "bank",    required_argument, NULL, ARG_BANK    },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        /* Make sure the arguments list and the section list, stays in sync */
        assert_cc(_ARG_SECTION_FIRST + _UNIFIED_SECTION_MAX == _ARG_SECTION_LAST + 1);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help(0, NULL, NULL);
                        return 0;

                case ARG_VERSION:
                        return version();

                case _ARG_SECTION_FIRST..._ARG_SECTION_LAST: {
                        UnifiedSection section = c - _ARG_SECTION_FIRST;

                        r = parse_path_argument(optarg, /* suppress_root= */ false, arg_sections + section);
                        if (r < 0)
                                return r;
                        break;
                }

                case ARG_BANK: {
                        const EVP_MD *implementation;

                        implementation = EVP_get_digestbyname(optarg);
                        if (!implementation)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown bank '%s', refusing.", optarg);

                        if (strv_extend(&arg_banks, EVP_MD_name(implementation)) < 0)
                                return log_oom();

                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (strv_isempty(arg_banks)) {
                /* If no banks are specifically selected, pick all known banks */
                arg_banks = strv_new("SHA1", "SHA256", "SHA384", "SHA512");
                if (!arg_banks)
                        return log_oom();
        }

        strv_sort(arg_banks);
        strv_uniq(arg_banks);

        return 1;
}

typedef struct PcrState {
        const EVP_MD *md;
        void *value;
        size_t value_size;
} PcrState;

static void pcr_state_free_all(PcrState **pcr_state) {
        assert(pcr_state);

        if (!*pcr_state)
                return;

        for (size_t i = 0; (*pcr_state)[i].value; i++)
                free((*pcr_state)[i].value);

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
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize %s context.", EVP_MD_name(pcr_state->md));

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

static int measure_pcr(PcrState *pcr_states, size_t n) {
        _cleanup_free_ void *buffer = NULL;
        int r;

        assert(n > 0);
        assert(pcr_states);

        buffer = malloc(BUFFER_SIZE);
        if (!buffer)
                return log_oom();

        for (UnifiedSection c = 0; c < _UNIFIED_SECTION_MAX; c++) {
                _cleanup_(evp_md_ctx_free_all) EVP_MD_CTX **mdctx = NULL;
                _cleanup_close_ int fd = -1;
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
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize data %s context.", EVP_MD_name(pcr_states[i].md));
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
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to hash section name with %s.", EVP_MD_name(pcr_states[i].md));

                        assert(data_hash_size == (unsigned) pcr_states[i].value_size);

                        r = pcr_state_extend(pcr_states + i, data_hash, data_hash_size);
                        if (r < 0)
                                return r;

                        /* Retrieve hash of data an measure it*/
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

static int verb_calculate(int argc, char *argv[], void *userdata) {
        _cleanup_(pcr_state_free_all) PcrState *pcr_states = NULL;
        size_t n = 0;
        int r;

        if (!arg_sections[UNIFIED_SECTION_LINUX])
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--linux= switch must be specified, refusing.");

        pcr_states = new0(PcrState, strv_length(arg_banks) + 1);
        if (!pcr_states)
                return log_oom();

        /* Allocate a PCR state structure, one for each bank */
        STRV_FOREACH(d, arg_banks) {
                const EVP_MD *implementation;
                _cleanup_free_ void *v = NULL;
                int sz;

                assert_se(implementation = EVP_get_digestbyname(*d)); /* Must work, we already checked while parsing  command line */

                sz = EVP_MD_size(implementation);
                if (sz <= 0 || sz >= INT_MAX)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unexpected digest size: %i", sz);

                v = malloc0(sz); /* initial PCR state is all zeroes */
                if (!v)
                        return log_oom();

                pcr_states[n++] = (struct PcrState) {
                        .md = implementation,
                        .value = TAKE_PTR(v),
                        .value_size = sz,
                };
        }

        r = measure_pcr(pcr_states, n);
        if (r < 0)
                return r;

        for (size_t i = 0; i < n; i++) {
                _cleanup_free_ char *hd = NULL, *b = NULL;

                hd = hexmem(pcr_states[i].value, pcr_states[i].value_size);
                if (!hd)
                        return log_oom();

                b = strdup(EVP_MD_name(pcr_states[i].md));
                if (!b)
                        return log_oom();

                printf("%" PRIu32 ":%s=%s\n", TPM_PCR_INDEX_KERNEL_IMAGE, ascii_strlower(b), hd);
        }

        return 0;
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

        if (tpm2_support() != TPM2_SUPPORT_FULL)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Sorry, system lacks full TPM2 support.");

        r = efi_stub_get_features(&features);
        if (r < 0)
                return log_error_errno(r, "Unable to get stub features: %m");

        if (!FLAGS_SET(features, EFI_STUB_FEATURE_THREE_PCRS))
                log_warning("Warning: current kernel image does not support measuring itself, the command line or initrd system extension images.\n"
                            "The PCR measurements seen are unlikely to be valid.");

        r = compare_reported_pcr_nr(TPM_PCR_INDEX_KERNEL_IMAGE, EFI_LOADER_VARIABLE("StubPcrKernelImage"), "kernel image");
        if (r < 0)
                return r;

        r = compare_reported_pcr_nr(TPM_PCR_INDEX_KERNEL_PARAMETERS, EFI_LOADER_VARIABLE("StubPcrKernelParameters"), "kernel parameters");
        if (r < 0)
                return r;

        r = compare_reported_pcr_nr(TPM_PCR_INDEX_INITRD_SYSEXTS, EFI_LOADER_VARIABLE("StubPcrInitRDSysExts"), "initrd system extension images");
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

        static const struct {
                uint32_t nr;
                const char *description;
        } relevant_pcrs[] = {
                { TPM_PCR_INDEX_KERNEL_IMAGE,      "Unified Kernel Image"     },
                { TPM_PCR_INDEX_KERNEL_PARAMETERS, "Kernel Parameters"        },
                { TPM_PCR_INDEX_INITRD_SYSEXTS,    "initrd System Extensions" },
        };

        int r;

        r = validate_stub();
        if (r < 0)
                return r;

        for (size_t i = 0; i < ELEMENTSOF(relevant_pcrs); i++) {

                STRV_FOREACH(bank, arg_banks) {
                        _cleanup_free_ char *b = NULL, *p = NULL, *s = NULL, *f = NULL;
                        _cleanup_free_ void *h = NULL;
                        size_t l;

                        b = strdup(*bank);
                        if (!b)
                                return log_oom();

                        if (asprintf(&p, "/sys/class/tpm/tpm0/pcr-%s/%" PRIu32, ascii_strlower(b), relevant_pcrs[i].nr) < 0)
                                return log_oom();

                        r = read_virtual_file(p, 4096, &s, NULL);
                        if (r == -ENOENT)
                                continue;
                        if (r < 0)
                                return log_error_errno(r, "Failed to read '%s': %m", p);

                        r = unhexmem(strstrip(s), SIZE_MAX, &h, &l);
                        if (r < 0)
                                return log_error_errno(r, "Failed to decode PCR value '%s': %m", s);

                        f = hexmem(h, l);
                        if (!h)
                                return log_oom();

                        if (bank == arg_banks) {
                                /* before the first line for each PCR, write a short descriptive text to
                                 * stderr, and leave the primary content on stdout */
                                fflush(stdout);
                                fprintf(stderr, "%s# PCR[%" PRIu32 "] %s%s%s\n",
                                        ansi_grey(),
                                        relevant_pcrs[i].nr,
                                        relevant_pcrs[i].description,
                                        memeqzero(h, l) ? " (NOT SET!)" : "",
                                        ansi_normal());
                                fflush(stderr);
                        }

                        printf("%" PRIu32 ":%s=%s\n", relevant_pcrs[i].nr, b, f);
                }
        }

        return 0;
}

static int measure_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",      VERB_ANY, VERB_ANY, 0,            help           },
                { "status",    VERB_ANY, 1,        VERB_DEFAULT, verb_status    },
                { "calculate", VERB_ANY, 1,        0,            verb_calculate },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return measure_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
