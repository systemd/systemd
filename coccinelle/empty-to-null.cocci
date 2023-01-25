/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
/* Avoid running this transformation on the empty_to_null macro itself.
 * See the note in strempty.cocci to understand the weird magic below.
*/
position p : script:python() {
        not (p[0].file == "src/basic/string-util.h" and p[0].current_element == "something_else")
};
expression s;
@@

- isempty@p(s) ? NULL : s
+ empty_to_null(s)
