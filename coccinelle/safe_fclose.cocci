/* SPDX-License-Identifier: LGPL-2.1-or-later */
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
