/* SPDX-License-Identifier: LGPL-2.1-or-later */
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
@@
expression f, fd, options;
@@
- f = fdopen(fd, options);
+ r = fdopen_unlocked(fd, options, &f);
+ if (r < 0) {
- if (!f) {
        ...
-       return -errno;
+       return r;
  }
- (void) __fsetlocking(f, FSETLOCKING_BYCALLER);
@@
expression f, buf, sz;
@@
- f = open_memstream(&buf, &sz);
+ f = open_memstream_unlocked(&buf, &sz);
  if (!f)
        return ...;
- (void) __fsetlocking(f, FSETLOCKING_BYCALLER);
