/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression x;
constant USEC_INFINITY = USEC_INFINITY;
/* We want to stick with the literal expression in the implementation of timestamp_is_set(), i.e. in time-util.c */
position p : script:python() { p[0].file != "src/basic/time-util.h" };
@@
(
- x > 0 && x < USEC_INFINITY
+ timestamp_is_set(x)
|
- x < USEC_INFINITY && x > 0
+ timestamp_is_set(x)
|
- x@p > 0 && x != USEC_INFINITY
+ timestamp_is_set(x)
|
- x != USEC_INFINITY && x > 0
+ timestamp_is_set(x)
|
- x != 0 && x < USEC_INFINITY
+ timestamp_is_set(x)
|
- x < USEC_INFINITY && x != 0
+ timestamp_is_set(x)
|
- x != 0 && x != USEC_INFINITY
+ timestamp_is_set(x)
|
- x != USEC_INFINITY && x != 0
+ timestamp_is_set(x)
|
- !IN_SET(x, 0, USEC_INFINITY)
+ timestamp_is_set(x)
|
- !IN_SET(x, USEC_INFINITY, 0)
+ timestamp_is_set(x)
)
@@
expression x;
constant USEC_INFINITY = USEC_INFINITY;
@@
(
- x <= 0 || x >= USEC_INFINITY
+ !timestamp_is_set(x)
|
- x >= USEC_INFINITY || x <= 0
+ !timestamp_is_set(x)
|
- x <= 0 || x == USEC_INFINITY
+ !timestamp_is_set(x)
|
- x == USEC_INFINITY || x <= 0
+ !timestamp_is_set(x)
|
- x == 0 || x >= USEC_INFINITY
+ !timestamp_is_set(x)
|
- x >= USEC_INFINITY || x == 0
+ !timestamp_is_set(x)
|
- x == 0 || x == USEC_INFINITY
+ !timestamp_is_set(x)
|
- x == USEC_INFINITY || x == 0
+ !timestamp_is_set(x)
|
- IN_SET(x, 0, USEC_INFINITY)
+ !timestamp_is_set(x)
|
- IN_SET(x, USEC_INFINITY, 0)
+ !timestamp_is_set(x)
)
