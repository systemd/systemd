@@
expression p;
@@
- free(p);
- p = NULL;
+ p = mfree(p);
