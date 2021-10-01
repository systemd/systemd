/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
constant c;
@@
(
- errno == -c
+ errno == c
|
- errno != -c
+ errno != c
)
