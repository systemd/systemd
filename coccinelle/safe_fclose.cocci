@@
expression p;
@@
- if (p) {
-         fclose(p);
-         p = NULL;
- }
+ p = safe_fclose(p);
@@
expression p;
@@
- if (p)
-         fclose(p);
- p = NULL;
+ p = safe_fclose(p);
@@
expression p;
@@
- fclose(p);
- p = NULL;
+ p = safe_fclose(p);
@@
expression p;
@@
- if (p)
-         fclose(p);
+ safe_fclose(p);
