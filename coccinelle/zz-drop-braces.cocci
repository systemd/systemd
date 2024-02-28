/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
position p : script:python() { p[0].file != "src/journal/lookup3.c" };
expression e,e1;
@@
- if (e) {
+ if (e)
(
  e1@p;
|
  return e1@p;
)
- }
