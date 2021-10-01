/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
/* Disable this transformation in cases where it doesn't make sense or
 * where it makes the resulting expression more confusing
 */
position p : script:python() {
            not (p[0].file == "src/shared/securebits-util.h" or
                 p[0].file == "src/core/manager.h" or
                 p[0].current_element == "log_set_max_level_realm" or
                 p[0].current_element == "unichar_is_valid")
        };
expression x;
constant y;
@@
(
- ((x@p) & (y)) == (y)
+ FLAGS_SET(x, y)
|
- (x@p & (y)) == (y)
+ FLAGS_SET(x, y)
|
- ((x@p) & y) == y
+ FLAGS_SET(x, y)
)
