/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dlfcn-util.h"
#include "log.h"
#include "pcre2-util.h"

#if HAVE_PCRE2
static void *pcre2_dl = NULL;

pcre2_match_data* (*sym_pcre2_match_data_create)(uint32_t, pcre2_general_context *);
void (*sym_pcre2_match_data_free)(pcre2_match_data *);
void (*sym_pcre2_code_free)(pcre2_code *);
pcre2_code* (*sym_pcre2_compile)(PCRE2_SPTR, PCRE2_SIZE, uint32_t, int *, PCRE2_SIZE *, pcre2_compile_context *);
int (*sym_pcre2_get_error_message)(int, PCRE2_UCHAR *, PCRE2_SIZE);
int (*sym_pcre2_match)(const pcre2_code *, PCRE2_SPTR, PCRE2_SIZE, PCRE2_SIZE, uint32_t, pcre2_match_data *, pcre2_match_context *);
PCRE2_SIZE* (*sym_pcre2_get_ovector_pointer)(pcre2_match_data *);
#endif

int dlopen_pcre2(void) {
#if HAVE_PCRE2
        /* So here's something weird: PCRE2 actually renames the symbols exported by the library via C
         * macros, so that the exported symbols carry a suffix "_8" but when used from C the suffix is
         * gone. In the argument list below we ignore this mangling. Surprisingly (at least to me), we
         * actually get away with that. That's because DLSYM_ARG() useses STRINGIFY() to generate a string
         * version of the symbol name, and that resolves the macro mapping implicitly already, so that the
         * string actually contains the "_8" suffix already due to that and we don't have to append it
         * manually anymore. C is weird. 🤯 */

        return dlopen_many_sym_or_warn(
                        &pcre2_dl, "libpcre2-8.so.0", LOG_ERR,
                        DLSYM_ARG(pcre2_match_data_create),
                        DLSYM_ARG(pcre2_match_data_free),
                        DLSYM_ARG(pcre2_code_free),
                        DLSYM_ARG(pcre2_compile),
                        DLSYM_ARG(pcre2_get_error_message),
                        DLSYM_ARG(pcre2_match),
                        DLSYM_ARG(pcre2_get_ovector_pointer));
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "PCRE2 support is not compiled in.");
#endif
}

int pattern_compile_and_log(const char *pattern, PatternCompileCase case_, pcre2_code **ret) {
#if HAVE_PCRE2
        PCRE2_SIZE erroroffset;
        pcre2_code *p;
        unsigned flags = 0;
        int errorcode, r;

        assert(pattern);

        r = dlopen_pcre2();
        if (r < 0)
                return r;

        if (case_ == PATTERN_COMPILE_CASE_INSENSITIVE)
                flags = PCRE2_CASELESS;
        else if (case_ == PATTERN_COMPILE_CASE_AUTO) {
                _cleanup_(sym_pcre2_match_data_freep) pcre2_match_data *md = NULL;
                bool has_case;
                _cleanup_(sym_pcre2_code_freep) pcre2_code *cs = NULL;

                md = sym_pcre2_match_data_create(1, NULL);
                if (!md)
                        return log_oom();

                r = pattern_compile_and_log("[[:upper:]]", PATTERN_COMPILE_CASE_SENSITIVE, &cs);
                if (r < 0)
                        return r;

                r = sym_pcre2_match(cs, (PCRE2_SPTR8) pattern, PCRE2_ZERO_TERMINATED, 0, 0, md, NULL);
                has_case = r >= 0;

                flags = !has_case * PCRE2_CASELESS;
        }

        log_debug("Doing case %s matching based on %s",
                  flags & PCRE2_CASELESS ? "insensitive" : "sensitive",
                  case_ != PATTERN_COMPILE_CASE_AUTO ? "request" : "pattern casing");

        p = sym_pcre2_compile((PCRE2_SPTR8) pattern,
                              PCRE2_ZERO_TERMINATED, flags, &errorcode, &erroroffset, NULL);
        if (!p) {
                unsigned char buf[LINE_MAX];

                r = sym_pcre2_get_error_message(errorcode, buf, sizeof buf);

                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Bad pattern \"%s\": %s", pattern,
                                       r < 0 ? "unknown error" : (char *)buf);
        }

        if (ret)
                *ret = p;

        return 0;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "PCRE2 support is not compiled in.");
#endif
}

int pattern_matches_and_log(pcre2_code *compiled_pattern, const char *message, size_t size, size_t *ret_ovec) {
#if HAVE_PCRE2
        _cleanup_(sym_pcre2_match_data_freep) pcre2_match_data *md = NULL;
        int r;

        assert(compiled_pattern);
        assert(message);
        /* pattern_compile_and_log() must be called before this function is called and that function already
         * dlopens pcre2 so we can assert on it being available here. */
        assert(pcre2_dl);

        md = sym_pcre2_match_data_create(1, NULL);
        if (!md)
                return log_oom();

        r = sym_pcre2_match(compiled_pattern,
                            (const unsigned char *)message,
                            size,
                            0,      /* start at offset 0 in the subject */
                            0,      /* default options */
                            md,
                            NULL);
        if (r == PCRE2_ERROR_NOMATCH)
                return false;
        if (r < 0) {
                unsigned char buf[LINE_MAX];

                r = sym_pcre2_get_error_message(r, buf, sizeof(buf));
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Pattern matching failed: %s",
                                       r < 0 ? "unknown error" : (char*) buf);
        }

        if (ret_ovec) {
                ret_ovec[0] = sym_pcre2_get_ovector_pointer(md)[0];
                ret_ovec[1] = sym_pcre2_get_ovector_pointer(md)[1];
        }

        return true;
#else
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "PCRE2 support is not compiled in.");
#endif
}

void *pattern_free(pcre2_code *p) {
#if HAVE_PCRE2
        if (!p)
                return NULL;

        assert(pcre2_dl);
        sym_pcre2_code_free(p);
        return NULL;
#else
        assert(p == NULL);
        return NULL;
#endif
}
