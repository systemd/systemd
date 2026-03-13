/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Detect pointer parameters that are dereferenced without a prior NULL check
 * or assertion. In systemd style, non-optional pointer parameters should have
 * an assert() at the top of the function.
 *
 * Usage:
 *   spatch --sp-file coccinelle/check-pointer-deref.cocci --dir src/boot/
 *
 * Note: this is a context-mode rule (flags, does not auto-fix). Each flagged
 * dereference should be reviewed: if the parameter is never NULL, add
 * assert(param) at the top. If it can legitimately be NULL, add an if() guard.
 */
@@
identifier fn, param;
type T;
position p;
@@

fn(..., T *param, ...) {
  ... when != assert(param)
      when != assert(param != NULL)
      when != assert_se(param)
      when != assert_se(param != NULL)
      when != assert_return(param, ...)
      when != ASSERT_PTR(param)
      when != POINTER_MAY_BE_NULL(param)
      /* NULL-safe helpers used commonly enough in assert() to warrant inclusion
       * here. For less common cases, use POINTER_MAY_BE_NULL(param) instead of
       * extending this list. */
      when != assert(pidref_is_set(param))
      when != \( param == NULL \| param != NULL \| !param \)
* *param@p
  ...
}
