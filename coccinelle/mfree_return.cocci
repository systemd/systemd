@@
/* Avoid running this transformation on the mfree function itself */
position p : script:python() { p[0].current_element != "mfree" };
expression e;
@@
- free@p(e);
- return NULL;
+ return mfree(e);
