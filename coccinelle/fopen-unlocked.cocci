@@
expression f, path, options;
@@
- f = fopen(path, options);
- if (!f)
-       return -errno;
- (void) __fsetlocking(f, FSETLOCKING_BYCALLER);
+ r = fopen_unlocked(path, options, &f);
+ if (r < 0)
+       return r;
@@
expression f, path, options;
@@
- f = fopen(path, options);
- if (!f) {
-       if (errno == ENOENT)
-            return -ESRCH;
-       return -errno;
- }
- (void) __fsetlocking(f, FSETLOCKING_BYCALLER);
+ r = fopen_unlocked(path, options, &f);
+ if (r == -ENOENT)
+     return -ESRCH;
+ if (r < 0)
+       return r;
@@
expression f, path, options;
@@
- f = fopen(path, options);
- if (!f)
-       return errno == ENOENT ? -ESRCH : -errno;
- (void) __fsetlocking(f, FSETLOCKING_BYCALLER);
+ r = fopen_unlocked(path, options, &f);
+ if (r == -ENOENT)
+     return -ESRCH;
+ if (r < 0)
+       return r;
@@
expression f, path, p;
@@
  r = fopen_temporary(path, &f, &p);
  if (r < 0)
    return ...;
- (void) __fsetlocking(f, FSETLOCKING_BYCALLER);
@@
expression f, g, path, p;
@@
  r = fopen_temporary_label(path, g, &f, &p);
  if (r < 0)
    return ...;
- (void) __fsetlocking(f, FSETLOCKING_BYCALLER);
