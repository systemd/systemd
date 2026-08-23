/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* See: https://gcc.gnu.org/onlinedocs/gcc/Conditionals.html#Conditionals */
@@
expression e, x;
@@
- e ? e : x
+ e ?: x
