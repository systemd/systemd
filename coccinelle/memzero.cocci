/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
expression s;
@@
- memset(&s, 0, sizeof(s))
+ zero(s)
@@
expression s;
@@
- memset(s, 0, sizeof(*s))
+ zero(*s)
@@
expression s;
@@
- bzero(&s, sizeof(s))
+ zero(s)
@@
expression s;
@@
- bzero(s, sizeof(*s))
+ zero(*s)
@@
expression a, b;
@@
(
#define memzero
&
- memset(a, 0, b)
+ memzero(a, b)
)
@@
expression a, b;
@@
(
#define memzero
&
- bzero(a, b)
+ memzero(a, b)
)
