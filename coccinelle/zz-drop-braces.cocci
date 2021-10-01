/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
position p : script:python() { p[0].file != "src/journal/lookup3.c" };
identifier id;
expression e;
@@
if (...)
- {
(
    id@p(...);
|
    e@p;
)
- }

@@
position p : script:python() { p[0].file != "src/journal/lookup3.c" };
identifier id;
expression e;
@@
if (...)
- {
(
    return id@p(...);
|
    return e@p;
)
- }
