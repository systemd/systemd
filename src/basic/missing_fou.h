/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#if !HAVE_LINUX_FOU_H /* linux@23461551c00628c3f3fe9cf837bf53cf8f212b63 (3.18) */

#define FOU_GENL_NAME           "fou"
#define FOU_GENL_VERSION        0x1

enum {
        FOU_ATTR_UNSPEC,
        FOU_ATTR_PORT,                  /* u16 */
        FOU_ATTR_AF,                    /* u8 */
        FOU_ATTR_IPPROTO,               /* u8 */
        FOU_ATTR_TYPE,                  /* u8 */
        FOU_ATTR_REMCSUM_NOPARTIAL,     /* flag */

        __FOU_ATTR_MAX,
};

#define FOU_ATTR_MAX                (__FOU_ATTR_MAX - 1)

enum {
        FOU_CMD_UNSPEC,
        FOU_CMD_ADD,
        FOU_CMD_DEL,
        FOU_CMD_GET,

        __FOU_CMD_MAX,
};

enum {
        FOU_ENCAP_UNSPEC,
        FOU_ENCAP_DIRECT,
        FOU_ENCAP_GUE,
};

#define FOU_CMD_MAX        (__FOU_CMD_MAX - 1)

#else

#if !HAVE_FOU_ATTR_REMCSUM_NOPARTIAL /* linux@fe881ef11cf0220f118816181930494d484c4883 (4.0) */
#define FOU_ATTR_REMCSUM_NOPARTIAL 5

#undef  FOU_ATTR_MAX
#define FOU_ATTR_MAX               5
#endif

#if !HAVE_FOU_CMD_GET /* linux@7a6c8c34e5b71ac50e39588e20b39494a9e1d8e5 (4.1) */
#define FOU_CMD_GET 3

#undef  FOU_CMD_MAX
#define FOU_CMD_MAX 3
#endif

#endif
