/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#ifdef HAVE_TPM2

/* TPM2 marshalling macros. These generally don't need to be used outside of tpm2-util.c, but are here so
 * they can be tested by src/test/test-tpm2.c. */

/* Generic mappings for marshal/unmarshal type->function. Please add tests in src/test/test-tpm2.c for any
 * new types added here. Note that only the _MARSHAL() types need both normal and const types, as
 * _UNMARSHAL() requires non-const types. */
#define _MARSHAL(src)                                                   \
        _Generic(src,                                                   \
                 TPM2B_PRIVATE*: sym_Tss2_MU_TPM2B_PRIVATE_Marshal,     \
                 const TPM2B_PRIVATE*: sym_Tss2_MU_TPM2B_PRIVATE_Marshal, \
                 TPM2B_PUBLIC*: sym_Tss2_MU_TPM2B_PUBLIC_Marshal,       \
                 const TPM2B_PUBLIC*: sym_Tss2_MU_TPM2B_PUBLIC_Marshal)
#define _UNMARSHAL(dst)                                                 \
        _Generic(dst,                                                   \
                 TPM2B_PRIVATE*: sym_Tss2_MU_TPM2B_PRIVATE_Unmarshal,   \
                 TPM2B_PUBLIC*: sym_Tss2_MU_TPM2B_PUBLIC_Unmarshal)

/* Marshal src object into buf.
 *
 * The 'desc' arg must be a string describing what the source object is, e.g. "public key".
 *
 * The 'src' arg must be an object whose type is listed in _MARSHAL; otherwise the result is a compiler failure.
 *
 * The buffer 'buf' will be written into starting at the offset 'sizep' (using the value of sizep which must be a pointer).
 * The buffer size 'max' must be large enough to contain all the marshalled data, which is added to the
 * buffer starting at the offset from the value of the pointer 'sizep'. The 'sizep' pointer will be increased
 * by the size of the added data. */
#define tpm2_marshal(desc, src, buf, max, sizep)                        \
        UNIQ_tpm2_marshal(desc, src, buf, max, sizep, UNIQ)
#define UNIQ_tpm2_marshal(desc, src, buf, max, sizep, uniq)             \
        ({                                                              \
                const char *UNIQ_T(_desc, uniq) = (desc);               \
                typeof(src) UNIQ_T(_src, uniq) = (src);                 \
                uint8_t *UNIQ_T(_buf, uniq) = (uint8_t*)(buf);          \
                size_t UNIQ_T(_max, uniq) = (size_t)(max);              \
                typeof(sizep) UNIQ_T(_sizep, uniq) = (sizep);           \
                size_t UNIQ_T(_newsize, uniq);                          \
                TSS2_RC UNIQ_T(_rc, uniq);                              \
                int UNIQ_T(_r, uniq);                                   \
                _tpm2_marshal(UNIQ_T(_desc, uniq),                      \
                              UNIQ_T(_src, uniq),                       \
                              UNIQ_T(_buf, uniq),                       \
                              UNIQ_T(_max, uniq),                       \
                              UNIQ_T(_sizep, uniq),                     \
                              UNIQ_T(_newsize, uniq),                   \
                              UNIQ_T(_rc, uniq),                        \
                              UNIQ_T(_r, uniq));                        \
        })
#define _tpm2_marshal(desc, src, buf, max, sizep, newsize, rc, r)       \
        ({                                                              \
                log_debug("Marshalling %s", desc);                      \
                newsize = sizep ? *sizep : 0;                           \
                r = __tpm2_marshal(desc, src, buf, max, &newsize, rc);  \
                if (r == 0 && sizep)                                    \
                        *sizep = newsize;                               \
                r;                                                      \
        })
#define __tpm2_marshal(desc, src, buf, max, sizep, rc)                  \
        ({                                                              \
                rc = _MARSHAL(src)(src, buf, max, sizep);               \
                rc == TSS2_RC_SUCCESS ? (int)0 :                        \
                        log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), \
                                        "Failed to marshal %s: %s",     \
                                        desc,                           \
                                        sym_Tss2_RC_Decode(rc));        \
        })

/* This is the same as tpm2_marshal() but does not actually perform the marshalling, it only calls the Esys
 * function with a NULL buffer to calculate the required size for marshalling. See tpm2_marshal() for details
 * on parameter requirements. */
#define tpm2_marshal_size(desc, src, sizep)                             \
        UNIQ_tpm2_marshal_size(desc, src, sizep, UNIQ)
#define UNIQ_tpm2_marshal_size(desc, src, sizep, uniq)                  \
        ({                                                              \
                const char *UNIQ_T(_desc, uniq) = (desc);               \
                typeof(src) UNIQ_T(_src, uniq) = (src);                 \
                typeof(sizep) UNIQ_T(_sizep, uniq) = (sizep);           \
                size_t UNIQ_T(_newsize, uniq);                          \
                TSS2_RC UNIQ_T(_rc, uniq);                              \
                int UNIQ_T(_r, uniq);                                   \
                _tpm2_marshal_size(UNIQ_T(_desc, uniq),                 \
                                   UNIQ_T(_src, uniq),                  \
                                   UNIQ_T(_sizep, uniq),                \
                                   UNIQ_T(_newsize, uniq),              \
                                   UNIQ_T(_rc, uniq),                   \
                                   UNIQ_T(_r, uniq));                   \
        })
#define _tpm2_marshal_size(desc, src, sizep, newsize, rc, r)            \
        ({                                                              \
                newsize = *sizep;                                       \
                r = __tpm2_marshal(desc, src, NULL, SIZE_MAX, &newsize, rc); \
                if (r == 0) {                                           \
                        log_debug("Marshalling %s requires %zu bytes.", \
                                  desc, newsize - *sizep);              \
                        *sizep = newsize;                               \
                }                                                       \
                r;                                                      \
        })

/* Realloc the buffer to add the size required to marshal the src object, and then marshal into the new
 * space. Note that the 'bufp' parameter must be uint8_t**, and must point to a buffer compatible with
 * realloc(); it will be updated realloc(). See tpm2_marshal() for details on other parameter
 * requirements. Returns 0 or error. */
#define tpm2_marshal_realloc(desc, src, bufp, sizep)                    \
        UNIQ_tpm2_marshal_realloc(desc, src, bufp, sizep, UNIQ)
#define UNIQ_tpm2_marshal_realloc(desc, src, bufp, sizep, uniq)         \
        ({                                                              \
                const char *UNIQ_T(_desc, uniq) = (desc);               \
                typeof(src) UNIQ_T(_src, uniq) = (src);                 \
                typeof(bufp) UNIQ_T(_bufp, uniq) = (bufp);              \
                typeof(sizep) UNIQ_T(_sizep, uniq) = (sizep);           \
                size_t UNIQ_T(_newsize, uniq);                          \
                uint8_t *UNIQ_T(_buf, uniq);                            \
                TSS2_RC UNIQ_T(_rc, uniq);                              \
                int UNIQ_T(_r, uniq);                                   \
                _tpm2_marshal_realloc(UNIQ_T(_desc, uniq),              \
                                      UNIQ_T(_src, uniq),               \
                                      UNIQ_T(_bufp, uniq),              \
                                      UNIQ_T(_sizep, uniq),             \
                                      UNIQ_T(_newsize, uniq),           \
                                      UNIQ_T(_buf, uniq),               \
                                      UNIQ_T(_rc, uniq),                \
                                      UNIQ_T(_r, uniq));                \
        })
#define _tpm2_marshal_realloc(desc, src, bufp, sizep, newsize, buf, rc, r) \
        ({                                                              \
                newsize = *sizep;                                       \
                r = tpm2_marshal_size(desc, src, &newsize);             \
                if (r == 0) {                                           \
                        buf = realloc(*bufp, newsize);                  \
                        if (!buf)                                       \
                                r = log_oom();                          \
                        else {                                          \
                                *bufp = buf;                            \
                                r = __tpm2_marshal(desc, src, buf, newsize, sizep, rc); \
                        }                                               \
                }                                                       \
                r;                                                      \
        })

#define tpm2_unmarshal(desc, buf, max, offsetp, dst)                    \
        UNIQ_tpm2_unmarshal(desc, buf, max, offsetp, dst, UNIQ)
#define UNIQ_tpm2_unmarshal(desc, buf, max, offsetp, dst, uniq)         \
        ({                                                              \
                const char *UNIQ_T(_desc, uniq) = (desc);               \
                typeof(buf) UNIQ_T(_buf, uniq) = (buf);                 \
                typeof(max) UNIQ_T(_max, uniq) = (max);                 \
                typeof(offsetp) UNIQ_T(_offsetp, uniq) = (offsetp);     \
                typeof(dst) UNIQ_T(_dst, uniq) = (dst);                 \
                size_t UNIQ_T(_newsize, uniq);                          \
                TSS2_RC UNIQ_T(_rc, uniq);                              \
                int UNIQ_T(_r, uniq);                                   \
                _tpm2_unmarshal(UNIQ_T(_desc, uniq),                    \
                                UNIQ_T(_buf, uniq),                     \
                                UNIQ_T(_max, uniq),                     \
                                UNIQ_T(_offsetp, uniq),                 \
                                UNIQ_T(_dst, uniq),                     \
                                UNIQ_T(_newsize, uniq),                 \
                                UNIQ_T(_rc, uniq),                      \
                                UNIQ_T(_r, uniq));                      \
        })
#define _tpm2_unmarshal(desc, buf, max, offsetp, dst, newsize, rc, r)   \
        ({                                                              \
                log_debug("Unmarshalling %s", desc);                    \
                newsize = offsetp ? *offsetp : 0;                       \
                r = __tpm2_unmarshal(desc, buf, max, &newsize, dst, rc); \
                if (r == 0 && offsetp)                                  \
                        *offsetp = newsize;                             \
                r;                                                      \
        })
#define __tpm2_unmarshal(desc, buf, max, offsetp, dst, rc)              \
        ({                                                              \
                rc = _UNMARSHAL(dst)(buf, max, offsetp, dst);           \
                rc == TSS2_RC_SUCCESS ? (int)0                          \
                        : log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), \
                                          "Failed to unmarshal %s: %s", \
                                          desc,                         \
                                          sym_Tss2_RC_Decode(rc));      \
        })

#endif /* HAVE_TPM2 */
