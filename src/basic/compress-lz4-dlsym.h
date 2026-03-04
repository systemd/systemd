/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_LZ4
#include <lz4.h>
#endif

#include "dlfcn-util.h"

#if HAVE_LZ4
extern DLSYM_PROTOTYPE(LZ4_compress_default);
extern DLSYM_PROTOTYPE(LZ4_decompress_safe);
extern DLSYM_PROTOTYPE(LZ4_decompress_safe_partial);
extern DLSYM_PROTOTYPE(LZ4_versionNumber);
#endif
