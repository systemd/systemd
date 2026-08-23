/* SPDX-License-Identifier: LGPL-2.1-or-later */
@ depends on !(file in "src/libsystemd/sd-journal/lookup3.c") @
expression e, e1;
@@
- if (e) {
+ if (e)
(
  e1;
|
  return e1;
)
- }
