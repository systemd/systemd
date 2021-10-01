/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
/* Avoid running this transformation on the empty_to_null function itself */
position p : script:python() { p[0].current_element != "empty_to_null" };
expression s;
@@

- isempty@p(s) ? NULL : s
+ empty_to_null(s)
