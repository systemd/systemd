@@
expression p;
@@
- if (p) {
-         closedir(p);
-         p = NULL;
- }
+ p = safe_closedir(p);
@@
expression p;
@@
- if (p)
-         closedir(p);
- p = NULL;
+ p = safe_closedir(p);
@@
expression p;
@@
- closedir(p);
- p = NULL;
+ p = safe_closedir(p);
@@
expression p;
@@
- if (p)
-         closedir(p);
+ safe_closedir(p);
