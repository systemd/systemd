@@
expression p;
@@
- set_free(p);
- p = NULL;
+ p = set_free(p);
@@
expression p;
@@
- if (p)
-         set_free(p);
- p = NULL;
+ p = set_free(p);
@@
expression p;
@@
- if (p) {
-         set_free(p);
-         p = NULL;
- }
+ p = set_free(p);
@@
expression p;
@@
- if (p)
-         set_free(p);
+ set_free(p);
@@
expression p;
@@
- hashmap_free(p);
- p = NULL;
+ p = hashmap_free(p);
@@
expression p;
@@
- if (p)
-         hashmap_free(p);
- p = NULL;
+ p = hashmap_free(p);
@@
expression p;
@@
- if (p) {
-         hashmap_free(p);
-         p = NULL;
- }
+ p = hashmap_free(p);
@@
expression p;
@@
- if (p)
-         hashmap_free(p);
+ hashmap_free(p);
