@@
expression s;
@@
- s ?: ""
+ strempty(s)
@@
expression s;
@@
- s ? s : ""
+ strempty(s)
@@
expression s;
@@
- if (!s)
-         s = "";
+ s = strempty(s);
@@
expression s;
@@
- s ?: "(null)"
+ strnull(s)
@@
expression s;
@@
- s ? s : "(null)"
+ strnull(s)
@@
expression s;
@@
- if (!s)
-         s = "(null)";
+ s = strnull(s);
@@
expression s;
@@
- s ?: "n/a"
+ strna(s)
@@
expression s;
@@
- s ? s : "n/a"
+ strna(s)
@@
expression s;
@@
- if (!s)
-         s = "n/a";
+ s = strna(s);
