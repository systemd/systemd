@@
/* Avoid running this transformation on the strempty function itself */
position p : script:python() { p[0].current_element != "strempty" };
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
