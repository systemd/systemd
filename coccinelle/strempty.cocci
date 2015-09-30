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
