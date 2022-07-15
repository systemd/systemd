/* SPDX-License-Identifier: LGPL-2.1-or-later */
@@
/* Avoid running this transformation on the strempty function itself and
 * on the "make_expression" macro in src/libsystemd/sd-bus/bus-convenience.c.
 * As Coccinelle's Location object doesn't support macro "detection", use
 * a pretty horrifying combo of specifying a file and a special "something_else"
 * position element, which is, apparently, the default value of
 * "current_element" before it's set (according to the source code), thus
 * matching any "top level" position, including macros. Let's hope we never
 * introduce a function called "something_else"...
 */
position p : script:python() {
        not (p[0].current_element == "strempty" or
                (p[0].file == "src/libsystemd/sd-bus/bus-convenience.c" and
                        p[0].current_element == "something_else"))
};
expression s;
@@
(
- s@p ?: ""
+ strempty(s)
|
- s@p ? s : ""
+ strempty(s)
)

@@
position p : script:python() { p[0].current_element != "strempty" };
expression s;
@@
- if (!s@p)
-         s = "";
+ s = strempty(s);

@@
position p : script:python() { p[0].current_element != "strnull" };
expression s;
@@
(
- s@p ?: "(null)"
+ strnull(s)
|
- s@p ? s : "(null)"
+ strnull(s)
)

@@
position p : script:python() { p[0].current_element != "strnull" };
expression s;
@@
- if (!s@p)
-         s = "(null)";
+ s = strnull(s);

@@
position p : script:python() { p[0].current_element != "strna" };
expression s;
@@
(
- s@p ?: "n/a"
+ strna(s)
|
- s@p ? s : "n/a"
+ strna(s)
)

@@
position p : script:python() { p[0].current_element != "strna" };
expression s;
@@
- if (!s@p)
-         s = "n/a";
+ s = strna(s);
