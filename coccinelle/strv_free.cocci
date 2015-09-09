@@
expression p;
@@
- strv_free(p);
- p = NULL;
+ p = strv_free(p);
@@
expression p;
@@
- if (p)
-         strv_free(p);
- p = NULL;
+ p = strv_free(p);
@@
expression p;
@@
- if (p) {
-         strv_free(p);
-         p = NULL;
- }
+ p = strv_free(p);
@@
expression p;
@@
- if (p)
-         strv_free(p);
+ strv_free(p);
