@@
expression p, q;
@@
- free(p);
- p = q;
- q = NULL;
- return 0;
+ return free_and_replace(p, q);
@@
expression p, q;
@@
- free(p);
- p = q;
- q = NULL;
+ free_and_replace(p, q);
