/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Run through bindgen at configure time: it reports the libclang version and contains the construct that
 * bindgen < 0.72.1 mishandles with libclang >= 22 (https://github.com/rust-lang/rust-bindgen/pull/3278). */

#pragma message("clang version " __clang_version__)

struct S;
struct S {
        int foo;
};
