/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* TPM2 marshalling macros. These generally don't need to be used outside of tpm2-util.c, but are here so
 * they can be tested by src/test/test-tpm2.c. */

#include "variadic-fundamental.h"

#ifdef HAVE_TPM2

/* Generic mappings for marshal/unmarshal type->function. Note that these types should match exactly what is
 * expected by the corresponding TSS library MU function, which is usually a pointer.
 *
 * Please add tests in src/test/test-tpm2.c for any new types added here. */
#define _MARSHAL_TYPES                                                  \
        VA_GROUP(TPM2B_PRIVATE*: sym_Tss2_MU_TPM2B_PRIVATE_Marshal,     \
                 TPM2B_PUBLIC*: sym_Tss2_MU_TPM2B_PUBLIC_Marshal)
#define _UNMARSHAL_TYPES                                                \
        VA_GROUP(TPM2B_PRIVATE*: sym_Tss2_MU_TPM2B_PRIVATE_Unmarshal,   \
                 TPM2B_PUBLIC*: sym_Tss2_MU_TPM2B_PUBLIC_Unmarshal)

/* Mappings for the const version of each marshal type. This is needed as callers can pass either const or
 * non-const 'src' objects to tpm2_marshal(). Only non-const 'dst' may be used with tpm2_unmarshal(). */
#define _MARSHAL_CONST_TYPE_MACRO(c, i, v, ...) const v
#define _MARSHAL_CONST_TYPES VA_MACRO_FOREACH(_MARSHAL_CONST_TYPE_MACRO, _MARSHAL_TYPES)

#define _MARSHAL(src) _Generic(src, _MARSHAL_TYPES, _MARSHAL_CONST_TYPES)
#define _UNMARSHAL(dst) _Generic(dst, _UNMARSHAL_TYPES)

/* Marshal 'src' object into 'buf'.
 *
 * The 'desc' arg must be a string describing what the source object is, e.g. "public key".
 *
 * The 'src' arg must be an object whose type is listed in _MARSHAL_TYPES; otherwise the result is a compiler
 * failure. The data it contains is marshalled into 'buf'.
 *
 * The 'buf' arg is a uint8_t* buffer. After successful marshalling, it will contain the marshalled data from
 * 'src'.
 *
 * The 'max' arg indicates the allocated size of 'buf'.
 *
 * The 'sizep' is a pointer whose value indicates the current amount of the buffer 'buf' in use (i.e. the
 * offset where new data should be placed). After successful marshalling, its value is updated. It may be
 * NULL, which indicates the buffer is empty; note in this case there is no way to communicate the new size
 * of the buffer to the caller. */
#define tpm2_marshal(desc, src, buf, max, sizep)                        \
        VA_MACRO_HELPER(_tpm2_marshal,                                  \
                        /* uniq= */,                                    \
                        VA_GROUP(size_t, TSS2_RC, int),                 \
                        VA_GROUP((uint8_t*) buf, (size_t*) sizep),      \
                        VA_GROUP(desc, src, max),                       \
                        /* direct= */)
#define _tpm2_marshal(newsize, rc, r, buf, sizep, desc, src, max)       \
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

/* Calculate the required size to marshal 'src'.
 *
 * This is the same as tpm2_marshal() but does not actually perform the marshalling; it uses a NULL buffer to
 * calculate the required size for marshalling.
 *
 * The 'sizep' arg cannot be NULL. Returns 0 or error. */
#define tpm2_marshal_size(desc, src, sizep)                             \
        VA_MACRO_HELPER(_tpm2_marshal_size,                             \
                        /* uniq= */,                                    \
                        VA_GROUP(size_t, TSS2_RC, int),                 \
                        (size_t*) sizep,                                \
                        VA_GROUP(desc, src),                            \
                        /* direct= */)
#define _tpm2_marshal_size(newsize, rc, r, sizep, desc, src)            \
        ({                                                              \
                assert(sizep);                                          \
                newsize = *sizep;                                       \
                r = __tpm2_marshal_size(desc, src, &newsize, rc);       \
                if (r == 0) {                                           \
                        log_debug("Marshalling %s requires %zu bytes.", \
                                  desc, newsize - *sizep);              \
                        *sizep = newsize;                               \
                }                                                       \
                r;                                                      \
        })
#define __tpm2_marshal_size(desc, src, sizep, rc)                       \
        __tpm2_marshal(desc, src, NULL, SIZE_MAX, sizep, rc)

/* Marshal 'src' object into 'buf', reallocating 'buf' if needed.
 *
 * This is the same as tpm2_marshal() but will reallocate 'buf' if it does not contain enough available space
 * for the marshalling.
 *
 * The 'buf' arg may be NULL, which will allocate a new buffer; otherwise it must be a buffer compatible with
 * realloc(). The 'buf' arg may be updated to point to the reallocated location.
 *
 * The 'sizep' arg cannot be NULL. Returns 0 or error. */
#define tpm2_marshal_realloc(desc, src, buf, sizep)                     \
        VA_MACRO_HELPER(_tpm2_marshal_realloc,                          \
                        /* uniq= */,                                    \
                        VA_GROUP(uint8_t*, size_t, TSS2_RC, int),       \
                        (size_t*) sizep,                                \
                        VA_GROUP(desc, src),                            \
                        buf)
#define _tpm2_marshal_realloc(newbuf, newsize, rc, r, sizep, desc, src, buf) \
        ({                                                              \
                assert(sizep);                                          \
                newsize = *sizep;                                       \
                r = __tpm2_marshal_size(desc, src, &newsize, rc);       \
                if (r == 0) {                                           \
                        newbuf = realloc(buf, newsize);                 \
                        if (newbuf == NULL)                             \
                                r = log_oom();                          \
                        else                                            \
                                buf = newbuf;                           \
                }                                                       \
                if (r == 0)                                             \
                        r = __tpm2_marshal(desc, src, buf, newsize, sizep, rc); \
                r;                                                      \
        })

/* Unmarshall from 'buf' into object 'dst'.
 *
 * The 'desc' arg must be a string describing what the destination object is, e.g. "public key".
 *
 * The 'buf' arg is a uint8_t* containing the data to unmarshall.
 *
 * The 'size' arg is the size of 'buf'.
 *
 * The 'offsetp' arg is a pointer whose value is the offset into 'buf' where the unmarshalling should
 * start. If NULL, unmarshalling starts at 0. After successful unmarshalling, its value (if it is not NULL)
 * is increased by the size of the unmarshalled data.
 *
 * The 'dst' arg must be an object whose type is in _UNMARSHAL_TYPES; otherwise the result is a compiler
 * failure. After successful unmarshalling, it will contain the unmarshalled data. */
#define tpm2_unmarshal(desc, buf, size, offsetp, dst)                   \
        VA_MACRO_HELPER(_tpm2_unmarshal,                                \
                        /* uniq= */,                                    \
                        VA_GROUP(size_t, TSS2_RC, int),                 \
                        VA_GROUP((size_t*) offsetp, dst),               \
                        VA_GROUP(desc, buf, size),                      \
                        /* direct= */)
#define _tpm2_unmarshal(newoffset, rc, r, offsetp, dst, desc, buf, size) \
        ({                                                              \
                log_debug("Unmarshalling %s", desc);                    \
                newoffset = offsetp ? *offsetp : 0;                     \
                r = __tpm2_unmarshal(desc, buf, size, &newoffset, dst, rc); \
                if (r == 0 && offsetp)                                  \
                        *offsetp = newoffset;                           \
                r;                                                      \
        })
#define __tpm2_unmarshal(desc, buf, size, offsetp, dst, rc)             \
        ({                                                              \
                rc = _UNMARSHAL(dst)(buf, size, offsetp, dst);          \
                rc == TSS2_RC_SUCCESS ? (int)0                          \
                        : log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), \
                                          "Failed to unmarshal %s: %s", \
                                          desc,                         \
                                          sym_Tss2_RC_Decode(rc));      \
        })

#endif /* HAVE_TPM2 */
