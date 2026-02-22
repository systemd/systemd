---
title: Coding Style
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Coding Style

## Formatting

- 8ch indent, no tabs, except for files in `man/` which are 2ch indent, and
  still no tabs, and shell scripts, which are 4ch indent, and no tabs either.

- We prefer `/* comments */` over `// comments` in code you commit,
  please. This way `// comments` are left for developers to use for local,
  temporary commenting of code for debug purposes (i.e. uncommittable stuff),
  making such comments easily discernible from explanatory, documenting code
  comments (i.e. committable stuff).

- Don't break code lines too eagerly. We do **not** force line breaks at 80ch,
  all of today's screens should be much larger than that. But then again, don't
  overdo it, ~109ch should be enough really. The `.editorconfig`, `.vimrc` and
  `.dir-locals.el` files contained in the repository will set this limit up for
  you automatically, if you let them (as well as a few other things). Please
  note that emacs loads `.dir-locals.el` automatically, but vim needs to be
  configured to load `.vimrc`, see that file for instructions.

- If you break a function declaration over multiple lines, do it like this:

  ```c
  void some_function(
                  int foo,
                  bool bar,
                  char baz) {

          int a, b, c;
  ```

  (i.e. use double indentation — 16 spaces — for the parameter list and leave a
  newline between the function declaration and the first variable declaration.)

- Try to write this:

  ```c
  void foo() {
  }
  ```

  instead of this:

  ```c
  void foo()
  {
  }
  ```

- Function return types should be seen/written as whole, i.e. write this:

  ```c
  const char* foo(const char *input);
  ```

  instead of this:

  ```c
  const char *foo(const char *input);
  ```

- Casts should be written like this:

  ```c
  (const char*) s;
  ```

  instead of this:

  ```c
  (const char *)s;
  ```

- Single-line `if` blocks should not be enclosed in `{}`. Write this:

  ```c
  if (foobar)
          waldo();
  ```

  instead of this:

  ```c
  if (foobar) {
          waldo();
  }
  ```

- Do not write `foo ()`, write `foo()`.

- `else` blocks should generally start on the same line as the closing `}`:
  ```c
  if (foobar) {
          find();
          waldo();
  } else
          dont_find_waldo();
  ```

- Please define flags types like this:

  ```c
  typedef enum FoobarFlags {
          FOOBAR_QUUX  = 1 << 0,
          FOOBAR_WALDO = 1 << 1,
          FOOBAR_XOXO  = 1 << 2,
          …
  } FoobarFlags;
  ```

  i.e. use an enum for it, if possible. Indicate bit values via `1 <<`
  expressions, and align them vertically. Define both an enum and a type for
  it.

- If you define (non-flags) enums, follow this template:

  ```c
  typedef enum FoobarMode {
          FOOBAR_AAA,
          FOOBAR_BBB,
          FOOBAR_CCC,
          …
          _FOOBAR_MAX,
          _FOOBAR_INVALID = -EINVAL,
  } FoobarMode;
  ```

  i.e. define a `_MAX` enum for the largest defined enum value, plus one. Since
  this is not a regular enum value, prefix it with `_`. Also, define a special
  "invalid" enum value, and set it to `-EINVAL`. That way the enum type can
  safely be used to propagate conversion errors.

- If you define an enum in a public API, be extra careful, as the size of the
  enum might change when new values are added, which would break ABI
  compatibility. Since we typically want to allow adding new enum values to an
  existing enum type with later API versions, please use the
  `_SD_ENUM_FORCE_S64()` macro in the enum definition, which forces the size of
  the enum to be signed 64-bit wide.

- Empty lines to separate code blocks are a good thing, please add them
  abundantly. However, please stick to one at a time, i.e. multiple empty lines
  immediately following each other are not OK. Also, we try to keep function
  calls and their immediate error handling together. Hence:

  ```c
  /* → empty line here is good */
  r = some_function(…);
  /* → empty line here would be bad */
  if (r < 0)
          return log_error_errno(r, "Some function failed: %m");
  /* → empty line here is good */
  ```

- In shell scripts, do not use whitespace after the redirection operator
  (`>some/file` instead of `> some/file`, `<<EOF` instead of `<< EOF`).

## Code Organization and Semantics

- For our codebase we intend to use ISO C17 *with* GNU extensions (aka
  "gnu17"). Public APIs (i.e. those we expose via `libsystemd.so`
  i.e. `systemd/sd-*.h`) should only use ISO C89 however (with a very limited
  set of conservative and common extensions, such as fixed size integer types
  from `<inttypes.h>`), so that we don't force consuming programs into C17
  mode. (This discrepancy in particular means one thing: internally we use C99
  `bool` booleans, externally C89-compatible `int` booleans which generally
  have different size in memory and slightly different semantics, also see
  below.)  Both for internal and external code it's OK to use even newer
  features and GCC extension than "gnu17", as long as there's reasonable
  fallback #ifdeffery in place to ensure compatibility is retained with older
  compilers.

- Please name structures in `PascalCase` (with exceptions, such as public API
  structs), variables and functions in `snake_case`.

- Avoid static variables, except for caches and very few other cases. Think
  about thread-safety! While most of our code is never used in threaded
  environments, at least the library code should make sure it works correctly
  in them. Instead of doing a lot of locking for that, we tend to prefer using
  TLS to do per-thread caching (which only works for small, fixed-size cache
  objects), or we disable caching for any thread that is not the main
  thread. Use `is_main_thread()` to detect whether the calling thread is the
  main thread.

- Typically, function parameters fit into four categories: input parameters,
  mutable objects, call-by-reference return parameters that are initialized on
  success, and call-by-reference return parameters that are initialized on
  failure. Input parameters should always carry suitable `const` declarators if
  they are pointers, to indicate they are input-only and not changed by the
  function. The name of return parameters that are initialized on success
  should be prefixed with `ret_`, to clarify they are return parameters. The
  name of return parameters that are initialized on failure should be prefixed
  with `reterr_`. (Examples of such parameters: those which carry additional
  error information, such as the row/column of parse errors or so). –
  Conversely, please do not prefix parameters that aren't output-only with
  `ret_` or `reterr_`, in particular not mutable parameters that are both input
  as well as output.

  Example:

  ```c
  static int foobar_frobnicate(
                  Foobar *object,            /* the associated mutable object */
                  const char *input,         /* immutable input parameter */
                  char **ret_frobnicated,    /* return parameter on success */
                  unsigned *reterr_line,     /* return parameter on failure */
                  unsigned *reterr_column) { /* ditto */
          …
          return 0;
  }
  ```

- Do not write functions that clobber call-by-reference success return
  parameters on failure (i.e. `ret_xyz`, see above), or that clobber
  call-by-reference failure return parameters on success
  (i.e. `reterr_xyz`). Use temporary variables for these cases and change the
  passed in variables only in the right condition. The rule is: never clobber
  success return parameters on failure, always initialize success return
  parameters on success (and the reverse for failure return parameters, of
  course).

- Please put `reterr_` return parameters in the function parameter list last,
  and `ret_` return parameters immediately before that.

  Good:

  ```c
  static int do_something(
                  const char *input,
                  const char *ret_on_success,
                  const char *reterr_on_failure);
  ```

  Not good:

  ```c
  static int do_something(
                  const char *reterr_on_failure,
                  const char *ret_on_success,
                  const char *input);
  ```

- When passing `NULL` or another value meaning "unset" to a function, use a comment
  to indicate the argument name to make it more clear where we're passing an "unset"
  value.

  Bad:

  ```c
  myfunction(NULL, NULL, NULL);
  ```

  Good:

  ```c
  myfunction(/* a= */ NULL, /* b= */ NULL, /* c= */ NULL);
  ```

  This guidance should be applied tree-wide, including in test files.

- Please do not introduce new circular dependencies between header files.
  Effectively this means that if a.h includes b.h, then b.h cannot include a.h,
  directly or transitively via another header. Circular header dependencies can
  make for extremely confusing errors when modifying the headers, which can be
  easily avoided by getting rid of the circular dependency. To get rid of a
  circular header dependency, there are a few possible techniques:
  - Introduce a new common header with the declarations that need to be shared
    by both headers and include only this header in the other headers.
  - Move declarations around between the two headers so one header doesn't need
    to include the other header anymore.
  - Use forward declarations if possible to remove the need for one header to
    include the other. To make this possible, you can move the body of static
    inline functions that require the full definition of a struct into the
    implementation file so that only a forward declaration of the struct is
    required and not the full definition.
  - `src/basic/basic-forward.h` contains forward declarations for common types.
    If possible, only include `basic-forward.h` in header files which makes
    circular header dependencies a non-issue.

  Bad:

  ```c
  // manager.h

  typedef struct Manager Manager;

  #include "unit.h"

  struct Manager {
          Unit *unit;
  };

  // unit.h

  typedef struct Unit Unit;

  #include "manager.h"

  struct Unit {
          Manager *manager;
  };
  ```

  Good:

  ```c
  // manager.h

  typedef struct Unit Unit;

  typedef struct Manager {
          Unit *unit;
  } Manager;

  // manager.c

  #include "unit.h"

  // unit.h

  typedef struct Manager Manager;

  typedef struct Unit {
          Manager *manager;
  } Unit;

  // unit.c

  #include "manager.h"
  ```

- Please keep header files as lean as possible. Prefer implementing functions in
  the implementation (.c) file over implementing them in the corresponding
  header file. Inline functions in the header are allowed if they are just a few
  lines and don't require including any extra header files that would otherwise
  not have to be included. Keeping header files as lean as possible speeds up
  incremental builds when header files are changed (either by yourself when
  working on a pull request or as part of rebasing onto the main branch) as each
  file that (transitively) includes a header that was changed needs to be
  recompiled. By keeping the number of header files included by other header
  files low, we reduce the impact of modifying header files on
  incremental builds as much as possible.

  To avoid having to include other headers in header files, always include
  the corresponding forward declaration header in each header file and then add
  other required includes as needed. The forward declaration header already
  includes generic headers and contains forward declarations for common types
  which should be sufficient for most header files. For each extra include you
  add on top of, check if it can be replaced by adding another forward
  declaration to the forward declaration header. Depending on the daemon, there
  might be a specific forward header to include (e.g. `resolved-forward.h` for
  systemd-resolved header files).

  For common code, there are three different forward declaration headers:

  - `src/basic`: `basic-forward.h`
  - `src/libsystemd`: `sd-forward.h`
  - `src/libsystemd-network`: `sd-forward.h`
  - `src/shared`: `shared-forward.h`

  Header files that extend other header files can include the original header
  file. For example, `iovec-util.h` includes `iovec-fundamental.h` and
  `sys/uio.h`. To identify headers that are exported from other headers, add a
  `IWYU pragma: export` comment to the includes so that these exports are
  recognized by clang static analysis tooling.

  Bad:

  ```c
  // source.h

  #include <stddef.h>

  #include "log.h"

  static inline void my_function_that_logs(size_t sz) {
          log_error("oops: %zu", sz);
  }
  ```

  Good:

  ```c
  // source.h

  #include "basic-forward.h"

  void my_function_that_logs(size_t sz);

  // source.c

  #include "source.h"
  #include "log.h"

  void my_function_that_logs(size_t sz) {
          log_error("oops: %zu", sz);
  }
  ```

- The order in which header files are included doesn't matter too
  much. systemd-internal headers must not rely on an include order, so it is
  safe to include them in any order possible.  However, to not clutter global
  includes, and to make sure internal definitions will not affect global
  headers, please always include the headers of external components first
  (these are all headers enclosed in <>), followed by our own exported headers
  (usually everything that's prefixed by `sd-`), and then followed by internal
  headers.  Furthermore, in all three groups, order all includes alphabetically
  so duplicate includes can easily be detected.

- Please avoid using global variables as much as you can. And if you do use
  them make sure they are static at least, instead of exported. Especially in
  library-like code it is important to avoid global variables. Why are global
  variables bad? They usually hinder generic reusability of code (since they
  break in threaded programs, and usually would require locking there), and as
  the code using them has side-effects make programs non-transparent. That
  said, there are many cases where they explicitly make a lot of sense, and are
  OK to use. For example, the log level and target in `log.c` is stored in a
  global variable, and that's OK and probably expected by most. Also in many
  cases we cache data in global variables. If you add more caches like this,
  please be careful however, and think about threading. Only use static
  variables if you are sure that thread-safety doesn't matter in your
  case. Alternatively, consider using TLS, which is pretty easy to use with
  gcc's `thread_local` concept. It's also OK to store data that is inherently
  global in global variables, for example, data parsed from command lines, see
  below.

- Our focus is on the GNU libc (glibc), not any other libcs. If other libcs are
  incompatible with glibc it's on them. However, if there are equivalent POSIX
  and Linux/GNU-specific APIs, we generally prefer the POSIX APIs. If there
  aren't, we are happy to use GNU or Linux APIs, and expect non-GNU
  implementations of libc to catch up with glibc.

- Very often we pass a pair of file descriptor and a path to functions, which
  are to be understood in combination. For example `openat()` style functions
  typically take a directory fd and a filename relative to that as argument. In
  other cases where operations operate relative to a root directory it makes
  sense to have a pair of root path and root fd. Whenever possible the function
  arguments should be in the order "fd first, path second" when the path shall
  be understood relative to the fd. And an order "path first, fd second"
  shall be used when the root path is the path of the referenced fd, i.e. two
  references to the same object.

## Using C Constructs

- Allocate local variables where it makes sense: at the top of the block, or at
  the point where they can be initialized. Avoid huge variable declaration
  lists at the top of the function.

  As an exception, `int r` is typically used for a local state variable, but
  should almost always be declared as the last variable at the top of the
  function.

  ```c
  {
          uint64_t a;
          int r;

          r = frobnicate(&a);
          if (r < 0)
                  …

          uint64_t b = a + 1, c;

          r = foobarify(a, b, &c);
          if (r < 0)
                  …

          const char *pretty = prettify(a, b, c);
          …
  }
  ```

- Do not mix multiple variable definitions with function invocations or
  complicated expressions:

  ```c
  {
          uint64_t x = 7;
          int a;

          a = foobar();
  }
  ```

  instead of:

  ```c
  {
          int a = foobar();
          uint64_t x = 7;
  }
  ```

- Use `goto` for cleaning up, and only use it for that. I.e. you may only jump
  to the end of a function, and little else. Never jump backwards!

- To minimize strict aliasing violations, we prefer unions over casting.

- Instead of using `memzero()`/`memset()` to initialize structs allocated on
  the stack, please try to use c99 structure initializers. It's short, prettier
  and actually even faster at execution. Hence:

  ```c
  struct foobar t = {
          .foo = 7,
          .bar = "bazz",
  };
  ```

  instead of:

  ```c
  struct foobar t;
  zero(t);
  t.foo = 7;
  t.bar = "bazz";
  ```

- To implement an endless loop, use `for (;;)` rather than `while (1)`. The
  latter is a bit ugly anyway, since you probably really meant `while
  (true)`. To avoid the discussion what the right always-true expression for an
  infinite while loop is, our recommendation is to simply write it without any
  such expression by using `for (;;)`.

- To determine the length of a constant string `"foo"`, don't bother with
  `sizeof("foo")-1`, please use `strlen()` instead (both gcc and clang optimize
  the call away for fixed strings). The only exception is when declaring an
  array. In that case use `STRLEN()`, which evaluates to a static constant and
  doesn't force the compiler to create a VLA.

- Please use C's downgrade-to-bool feature only for expressions that are
  actually booleans (or "boolean-like"), and not for variables that are really
  numeric. Specifically, if you have an `int b` and it's only used in a boolean
  sense, by all means check its state with `if (b) …` — but if `b` can actually
  have more than two semantic values, and you want to compare for non-zero,
  then please write that explicitly with `if (b != 0) …`. This helps readability
  as the value range and semantical behaviour is directly clear from the
  condition check. As a special addition: when dealing with pointers which you
  want to check for non-NULL-ness, you may also use downgrade-to-bool feature.

- Please do not use yoda comparisons, i.e. please prefer the more readable `if
  (a == 7)` over the less readable `if (7 == a)`.

## Destructors

- The destructors always deregister the object from the next bigger object, not
  the other way around.

- For robustness reasons, destructors should be able to destruct
  half-initialized objects, too.

- When you define a destructor or `unref()` call for an object, please accept a
  `NULL` object and simply treat this as NOP. This is similar to how libc
  `free()` works, which accepts `NULL` pointers and becomes a NOP for them. By
  following this scheme a lot of `if` checks can be removed before invoking
  your destructor, which makes the code substantially more readable and robust.

- Related to this: when you define a destructor or `unref()` call for an
  object, please make it return the same type it takes and always return `NULL`
  from it. This allows writing code like this:

  ```c
  p = foobar_unref(p);
  ```

  which will always work regardless if `p` is initialized or not, and
  guarantees that `p` is `NULL` afterwards, all in just one line.

## Common Function Naming

- Name destructor functions that destroy an object in full freeing all its
  memory and associated resources (and thus invalidating the pointer to it)
  `xyz_free()`. Example: `strv_free()`.

- Name destructor functions that destroy only the referenced content of an
  object but leave the object itself allocated `xyz_done()`. If it resets all
  fields so that the object can be reused later call it `xyz_clear()`.

- Functions that decrease the reference counter of an object by one should be
  called `xyz_unref()`. Example: `json_variant_unref()`. Functions that
  increase the reference counter by one should be called `xyz_ref()`. Example:
  `json_variant_ref()`

## Error Handling

- Error codes are returned as negative `Exxx`. e.g. `return -EINVAL`. There are
  some exceptions: for constructors, it is OK to return `NULL` on OOM. For
  lookup functions, `NULL` is fine too for "not found".

  Be strict with this. When you write a function that can fail due to more than
  one cause, it *really* should have an `int` as the return value for the error
  code.

- libc system calls typically return -1 on error (with the error code in
  `errno`), and >= 0 on success. Use the RET_NERRNO() helper if you are looking
  for a simple way to convert this libc style error returning into systemd
  style error returning. e.g.

  ```c
  …
  r = RET_NERRNO(unlink(t));
  …
  ```

  or

  ```c
  …
  r = RET_NERRNO(open("/some/file", O_RDONLY|O_CLOEXEC));
  …
  ```

- Do not bother with error checking whether writing to stdout/stderr worked.

- Do not log errors from "library" code, only do so from "main program"
  code. (With one exception: it is OK to log with DEBUG level from any code,
  with the exception of maybe inner loops).

- In libsystemd public API calls, you **must** validate all your input arguments
  for programming error with `assert_return()` and return a sensible return
  code. In all other calls, it is recommended to check for programming errors
  with a more brutal `assert()`. We are more forgiving to public users than for
  ourselves! Note that `assert()` and `assert_return()` really only should be
  used for detecting programming errors, not for runtime errors. `assert()` and
  `assert_return()` by usage of `_likely_()` inform the compiler that it should
  not expect these checks to fail, and they inform fellow programmers about the
  expected validity and range of parameters.

- When you invoke certain calls like `unlink()`, or `mkdir_p()` and you know it
  is safe to ignore the error it might return (because a later call would
  detect the failure anyway, or because the error is in an error path and you
  thus couldn't do anything about it anyway), then make this clear by casting
  the invocation explicitly to `(void)`. Code checks like Coverity understand
  that, and will not complain about ignored error codes. Hence, please use
  this:

  ```c
  (void) unlink("/foo/bar/baz");
  ```

  instead of just this:

  ```c
  unlink("/foo/bar/baz");
  ```

  When returning from a `void` function, you may also want to shorten the error
  path boilerplate by returning a function invocation cast to `(void)` like so:

  ```c
  if (condition_not_met)
          return (void) log_tests_skipped("Cannot run ...");
  ```

  Don't cast function calls to `(void)` that return no error
  conditions. Specifically, the various `xyz_unref()` calls that return a
  `NULL` object shouldn't be cast to `(void)`, since not using the return value
  does not hide any errors.

- When returning a return code from `main()`, please preferably use
  `EXIT_FAILURE` and `EXIT_SUCCESS` as defined by libc.

## Logging

- For every function you add, think about whether it is a "logging" function or
  a "non-logging" function. "Logging" functions do (non-debug) logging on their
  own, "non-logging" functions never log on their own (except at debug level)
  and expect their callers to log. All functions in "library" code, i.e. in
  `src/shared/` and suchlike must be "non-logging". Every time a "logging"
  function calls a "non-logging" function, it should log about the resulting
  errors. If a "logging" function calls another "logging" function, then it
  should not generate log messages, so that log messages are not generated
  twice for the same errors. (Note that debug level logging — at syslog level
  `LOG_DEBUG` — is not considered logging in this context, debug logging is
  generally always fine and welcome.)

- If possible, do a combined log & return operation:

  ```c
  r = operation(...);
  if (r < 0)
          return log_(error|warning|notice|...)_errno(r, "Failed to ...: %m");
  ```

  If the error value is "synthetic", i.e. it was not received from
  the called function, use `SYNTHETIC_ERRNO` wrapper to tell the logging
  system to not log the errno value, but still return it:

  ```c
  n = read(..., s, sizeof s);
  if (n != sizeof s)
          return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to read ...");
  ```

- When generating log messages that contain filenames, user controlled strings,
  or similar, please enclose them in single ticks.

- Think about the log level you choose: for functions that are of the "logging"
  kind (see above), please ensure that failures we propagate should be logged
  about at `LOG_ERR` level. Failures that are noteworthy, but we proceed anyway,
  should be logged at `LOG_WARN` level. Important informational messages should
  use `LOG_NOTICE` and regular informational messages should use
  `LOG_INFO`. Note that the latter is the default maximum log level, i.e. only
  `LOG_DEBUG` messages are hidden by default.

- All log messages that show some failure which is not fatal for the immediate
  operation (i.e. generally those you'd log at `LOG_WARN` level, as described
  above) should be suffixed with a `…, ignoring: %m"` or similar. Or in other
  words, they should make clear not only in log level but also in English
  language that the issue is not fatal, but ignored. Depending on context you
  can also use `…, proceeding anyway: %m"`, `…, skipping: %m` or other language
  that makes clear that the failure is not actionable and doesn't strictly
  require immediate administrator attention.

## Memory Allocation

- Always check OOM. There is no excuse. In program code, you can use
  `log_oom()` for then printing a short message, but not in "library" code.

- Avoid fixed-size string buffers, unless you really know the maximum size and
  that maximum size is small. It is often nicer to use dynamic memory,
  `alloca_safe()` or VLAs. If you do allocate fixed-size strings on the stack,
  then it is probably only OK if you either use a maximum size such as
  `LINE_MAX`, or count in detail the maximum size a string can
  have. (`DECIMAL_STR_MAX` and `DECIMAL_STR_WIDTH` macros are your friends for
  this!)

  Or in other words, if you use `char buf[256]` then you are likely doing
  something wrong!

- Make use of `_cleanup_free_` and friends. It makes your code much nicer to
  read (and shorter)!

- Do not use `alloca()`, `strdupa()` or `strndupa()` directly. Use
  `alloca_safe()`, `strdupa_safe()` or `strndupa_safe()` instead. (The
  difference is that the latter include an assertion that the specified size is
  below a safety threshold, so that the program rather aborts than runs into
  possible stack overruns.)

- Use `alloca_safe()`, but never forget that it is not OK to invoke
  `alloca_safe()` within a loop or within function call
  parameters. `alloca_safe()` memory is released at the end of a function, and
  not at the end of a `{}` block. Thus, if you invoke it in a loop, you keep
  increasing the stack pointer without ever releasing memory again. (VLAs have
  better behavior in this case, so consider using them as an alternative.)
  Regarding not using `alloca_safe()` within function parameters, see the BUGS
  section of the `alloca(3)` man page.

- If you want to concatenate two or more strings, consider using `strjoina()`
  or `strjoin()` rather than `asprintf()`, as the latter is a lot slower. This
  matters particularly in inner loops (but note that `strjoina()` cannot be
  used there).

## Runtime Behaviour

- Avoid leaving long-running child processes around, i.e. `fork()`s that are
  not followed quickly by an `execv()` in the child. Resource management is
  unclear in this case, and memory CoW will result in unexpected penalties in
  the parent much, much later on.

- Don't block execution for arbitrary amounts of time using `usleep()` or a
  similar call, unless you really know what you do. Just "giving something some
  time", or so is a lazy excuse. Always wait for the proper event, instead of
  doing time-based poll loops.

- Whenever installing a signal handler, make sure to set `SA_RESTART` for it,
  so that interrupted system calls are automatically restarted, and we minimize
  hassles with handling `EINTR` (in particular as `EINTR` handling is pretty
  broken on Linux).

- When applying C-style unescaping as well as specifier expansion on the same
  string, always apply the C-style unescaping first, followed by the specifier
  expansion. When doing the reverse, make sure to escape `%` in specifier-style
  first (i.e. `%` → `%%`), and then do C-style escaping where necessary.

- Be exceptionally careful when formatting and parsing floating point
  numbers. Their syntax is locale dependent (i.e. `5.000` in en_US is generally
  understood as 5, while in de_DE as 5000.).

- Make sure to enforce limits on every user controllable resource. If the user
  can allocate resources in your code, your code must enforce some form of
  limits after which it will refuse operation. It's fine if it is hard-coded
  (at least initially), but it needs to be there. This is particularly
  important for objects that unprivileged users may allocate, but also matters
  for everything else any user may allocate.

- Please use `secure_getenv()` for all environment variable accesses, unless
  it's clear that `getenv()` would be the better choice. This matters in
  particular in `src/basic/` and `src/shared/` (i.e. library code that might
  end up in unexpected processes), but should be followed everywhere else too
  (in order to make it unproblematic to move code around). To say this clearly:
  the default should be `secure_getenv()`, the exception should be regular
  `getenv()`.

## Types

- Think about the types you use. If a value cannot sensibly be negative, do not
  use `int`, but use `unsigned`.  We prefer `unsigned` form to `unsigned int`.

- Use `char` only for actual characters. Use `uint8_t` or `int8_t` when you
  actually mean a byte-sized signed or unsigned integers. When referring to a
  generic byte, we generally prefer the unsigned variant `uint8_t`. Do not use
  types based on `short`. They *never* make sense. Use `int`, `long`, `long
  long`, all in unsigned and signed fashion, and the fixed-size types
  `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`, `int8_t`, `int16_t`, `int32_t`
  and so on, as well as `size_t`, but nothing else. Do not use kernel types
  like `u32` and so on, leave that to the kernel.

- Stay uniform. For example, always use `usec_t` for time values. Do not mix
  `usec` and `msec`, and `usec` and whatnot.

- Never use the `off_t` type, and particularly avoid it in public APIs. It's
  really weirdly defined, as it usually is 64-bit and we don't support it any
  other way, but it could in theory also be 32-bit. Which one it is depends on
  a compiler switch chosen by the compiled program, which hence corrupts APIs
  using it unless they can also follow the program's choice. Moreover, in
  systemd we should parse values the same way on all architectures and cannot
  expose `off_t` values over D-Bus. To avoid any confusion regarding conversion
  and ABIs, always use simply `uint64_t` directly.

- Unless you allocate an array, `double` is always a better choice than
  `float`. Processors speak `double` natively anyway, so there is no speed
  benefit, and on calls like `printf()` `float`s get promoted to `double`s
  anyway, so there is no point.

- Use the bool type for booleans, not integers. One exception: in public
  headers (i.e those in `src/systemd/sd-*.h`) use integers after all, as `bool`
  is C99 and in our public APIs we try to stick to C89 (with a few extensions;
  also see above).

## Deadlocks

- Do not issue NSS requests (that includes user name and hostname lookups)
  from PID 1 as this might trigger deadlocks when those lookups involve
  synchronously talking to services that we would need to start up.

- Do not synchronously talk to any other service from PID 1, due to risk of
  deadlocks.

## File Descriptors

- When you allocate a file descriptor, it should be made `O_CLOEXEC` right from
  the beginning, as none of our files should leak to forked binaries by
  default. Hence, whenever you open a file, `O_CLOEXEC` must be specified,
  right from the beginning. This also applies to sockets. Effectively, this
  means that all invocations to:

  - `open()` must get `O_CLOEXEC` passed,
  - `socket()` and `socketpair()` must get `SOCK_CLOEXEC` passed,
  - `recvmsg()` must get `MSG_CMSG_CLOEXEC` set,
  - `F_DUPFD_CLOEXEC` should be used instead of `F_DUPFD`, and so on,
  - invocations of `fopen()` should take `e`.

- It's a good idea to use `O_NONBLOCK` when opening 'foreign' regular files,
  i.e.  file system objects that are supposed to be regular files whose paths
  were specified by the user and hence might actually refer to other types of
  file system objects. This is a good idea so that we don't end up blocking on
  'strange' file nodes, for example, if the user pointed us to a FIFO or device
  node which may block when opening. Moreover even for actual regular files
  `O_NONBLOCK` has a benefit: it bypasses any mandatory lock that might be in
  effect on the regular file. If in doubt consider turning off `O_NONBLOCK`
  again after opening.

- These days we generally prefer `openat()`-style file APIs, i.e. APIs that
  accept a combination of file descriptor and path string, and where the path
  (if not absolute) is considered relative to the specified file
  descriptor. When implementing library calls in similar style, please make
  sure to imply `AT_EMPTY_PATH` if an empty or `NULL` path argument is
  specified (and convert that latter to an empty string). This differs from the
  underlying kernel semantics, where `AT_EMPTY_PATH` must always be specified
  explicitly, and `NULL` is not accepted as path.

## Command Line

- If you parse a command line, and want to store the parsed parameters in
  global variables, please consider prefixing their names with `arg_`. We have
  been following this naming rule in most of our tools, and we should continue
  to do so, as it makes it easy to identify command line parameter variables,
  and makes it clear why it is OK that they are global variables.

- Command line option parsing:
  - Do not print full `help()` on error, be specific about the error.
  - Do not print messages to stdout on error.
  - Do not POSIX_ME_HARDER unless necessary, i.e. avoid `+` in option string.

## Exporting Symbols

- Variables and functions **must** be static, unless they have a prototype, and
  are supposed to be exported.

- Public API calls (i.e. functions exported by our shared libraries)
  must be marked `_public_` and need to be prefixed with `sd_`. No
  other functions should be prefixed like that.

- When exposing public C APIs, be careful what function parameters you make
  `const`. For example, a parameter taking a context object should probably not
  be `const`, even if you are writing an otherwise read-only accessor function
  for it. The reason is that making it `const` fixates the contract that your
  call won't alter the object ever, as part of the API. However, that's often
  quite a promise, given that this even prohibits object-internal caching or
  lazy initialization of object variables. Moreover, it's usually not too
  useful for client applications. Hence, please be careful and avoid `const` on
  object parameters, unless you are very sure `const` is appropriate.

## Referencing Concepts

- When referring to a configuration file option in the documentation and such,
  please always suffix it with `=`, to indicate that it is a configuration file
  setting.

- When referring to a command line option in the documentation and such, please
  always prefix with `--` or `-` (as appropriate), to indicate that it is a
  command line option.

- When referring to a file system path that is a directory, please always
  suffix it with `/`, to indicate that it is a directory, not a regular file
  (or other file system object).

## Functions to Avoid

- Use `memzero()` or even better `zero()` instead of `memset(..., 0, ...)`

- Please use `streq()` and `strneq()` instead of `strcmp()`, `strncmp()` where
  applicable (i.e. wherever you just care about equality/inequality, not about
  the sorting order).

- Never use `strtol()`, `atoi()` and similar calls. Use `safe_atoli()`,
  `safe_atou32()` and suchlike instead. They are much nicer to use in most
  cases and correctly check for parsing errors.

- `htonl()`/`ntohl()` and `htons()`/`ntohs()` are weird. Please use `htobe32()`
  and `htobe16()` instead, it's much more descriptive, and actually says what
  really is happening, after all `htonl()` and `htons()` don't operate on
  `long`s and `short`s as their name would suggest, but on `uint32_t` and
  `uint16_t`. Also, "network byte order" is just a weird name for "big endian",
  hence we might want to call it "big endian" right-away.

- Use `typesafe_inet_ntop()`, `typesafe_inet_ntop4()`, and
  `typesafe_inet_ntop6()` instead of `inet_ntop()`. But better yet, use the
  `IN_ADDR_TO_STRING()`, `IN4_ADDR_TO_STRING()`, and `IN6_ADDR_TO_STRING()`
  macros which allocate an anonymous buffer internally.

- Please never use `dup()`. Use `fcntl(fd, F_DUPFD_CLOEXEC, 3)` instead. For
  two reasons: first, you want `O_CLOEXEC` set on the new `fd` (see
  above). Second, `dup()` will happily duplicate your `fd` as 0, 1, 2,
  i.e. stdin, stdout, stderr, should those `fd`s be closed. Given the special
  semantics of those `fd`s, it's probably a good idea to avoid
  them. `F_DUPFD_CLOEXEC` with `3` as parameter avoids them.

- Don't use `fgets()`, it's too hard to properly handle errors such as overly
  long lines. Use `read_line()` instead, which is our own function that handles
  this much more nicely.

- Don't invoke `exit()`, ever. It is not replacement for proper error
  handling. Please escalate errors up your call chain, and use normal `return`
  to exit from the main function of a process. If you `fork()`ed off a child
  process, please use `_exit()` instead of `exit()`, so that the exit handlers
  are not run.

- Do not use `basename()` or `dirname()`. The semantics in corner cases are
  full of pitfalls, and the fact that there are two quite different versions of
  `basename()` (one POSIX and one GNU, of which the latter is much more useful)
  doesn't make it better either. Use path_extract_filename() and
  path_extract_directory() instead.

- Never use `FILENAME_MAX`. Use `PATH_MAX` instead (for checking maximum size
  of paths) and `NAME_MAX` (for checking maximum size of filenames).
  `FILENAME_MAX` is not POSIX, and is a confusingly named alias for `PATH_MAX`
  on Linux. Note that `NAME_MAX` does not include space for a trailing `NUL`,
  but `PATH_MAX` does. UNIX FTW!

## Committing to git

- Commit message subject lines should be prefixed with an appropriate component
  name of some kind. For example, "journal: ", "nspawn: " and so on.

- Do not use "Signed-Off-By:" in your commit messages. That's a kernel thing we
  don't do in the systemd project.

## Commenting

- The best place for code comments and explanations is in the code itself. Only
  the second best is in git commit messages. The worst place is in the GitHub
  PR cover letter. Hence, whenever you type a commit message consider for a
  moment if what you are typing there wouldn't be a better fit for an in-code
  comment. And if you type the cover letter of a PR, think hard if this
  wouldn't be better as a commit message or even code comment. Comments are
  supposed to be useful for somebody who reviews the code, and hence hiding
  comments in git commits or PR cover letters makes reviews unnecessarily
  hard. Moreover, while we rely heavily on GitHub's project management
  infrastructure we'd like to keep everything that can reasonably be kept in
  the git repository itself in the git repository, so that we can theoretically
  move things elsewhere with the least effort possible.

- It's OK to reference GitHub PRs, GitHub issues and git commits from code
  comments. Cross-referencing code, issues, and documentation is a good thing.

- Reasonable use of non-ASCII Unicode UTF-8 characters in code comments is
  welcome. If your code comment contains an emoji or two this will certainly
  brighten the day of the occasional reviewer of your code. Really! 😊

## Threading

- We generally avoid using threads, to the level this is possible. In
  particular in the service manager/PID 1 threads are not OK to use. This is
  because you cannot mix memory allocation in threads with use of glibc's
  `clone()` call, or manual `clone()`/`clone3()` system call wrappers. Only
  glibc's own `fork()` call will properly synchronize the memory allocation
  locks around the process clone operation. This means that if a process is
  cloned via `clone()`/`clone3()` and another thread currently has the
  `malloc()` lock taken, it will be cloned in locked state to the child, and
  thus can never be acquired in the child, leading to deadlocks. Hence, when
  using `clone()`/`clone3()` there are only two ways out: never use threads in the
  parent, or never do memory allocation in the child. For our uses we need
  `clone()`/`clone3()` and hence decided to avoid threads. Of course, sometimes the
  concurrency threads allow is beneficial, however we suggest forking off
  worker *processes* rather than worker *threads* for this purpose, ideally
  even with an `execve()` to remove the CoW trap situation `fork()` easily
  triggers.

- A corollary of the above is: never use `clone()` where a `fork()` would do
  too. Also consider using `posix_spawn()` which combines `clone()` +
  `execve()` into one and has nice properties since it avoids becoming a CoW
  trap by using `CLONE_VFORK` and `CLONE_VM` together.

- While we avoid forking off threads on our own, writing thread-safe code is a
  good idea where it might end up running inside of libsystemd.so or
  similar. Hence, use TLS (i.e. `thread_local`) where appropriate, and maybe
  the occasional `pthread_once()`.

## Tests

- Use the assertion macros from `tests.h` (`ASSERT_GE()`, `ASSERT_OK()`, ...) to
  make sure a descriptive error is logged when an assertion fails. If no assertion
  macro exists for your specific use case, please add a new assertion macro in a
  separate commit.

- Use `ASSERT_OK_ERRNO()` and similar macros instead of `ASSERT_OK()` when
  calling glibc APIs that return the error in `errno`.

- When modifying existing tests, please convert the test to use the new assertion
  macros from `tests.h` if it is not already using those.

## Integration Tests

- Never use `grep -q` in a pipeline, use `grep >/dev/null` instead. The former
  will generate `SIGPIPE` for the previous command in the pipeline when it finds
  a match which will cause the test to fail unexpectedly.

## Kernel Version Dependencies

- For entirely new functionality it's fine to rely on features of very recent
  (released!) kernel versions. If a feature is added to the upstream kernel,
  and a stable release is made, then it's immediately OK to merge *new*
  functionality into systemd relying on it, as long as that functionality is
  optional. (In some cases, it might be OK to merge a feature into systemd
  slightly before the final kernel release that it is based on, as long as the
  kernel development cycle has already progressed far enough that the feature
  is unlikely to be still reverted – for example once RC2 of the kernel release
  has been released.)

- For components that already have been released in a stable version
  compatibility with older kernels must be retained, down to the "minimum
  baseline" version as listed in the README, or the version current when the
  component was added to our tree, whichever is newer.

- When adding a fallback path, please avoid checking for kernel versions, as
  downstream distributions tend to backport features, and version checks are
  not great replacements for feature checks hence.

- When adding a compatibility code path for an older kernel version, please add
  a comment in the following style to the relevant codepath:

```c
        // FIXME: This compatibility code path shall be removed once kernel X.Y
        //        becomes the new minimal baseline
```

  When this syntax is followed we'll have an easier time tracking down these
  codepaths and removing them when bumping baselines.

- Whenever support for a new kernel API feature is added, please update the
  kernel feature/version list in README as well (as part of the same PR).
