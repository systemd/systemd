---
title: Testing systemd using sanitizers
---

# Testing systemd using sanitizers

To catch the *nastier* kind of bugs, you can run your code with [Address Sanitizer](https://clang.llvm.org/docs/AddressSanitizer.html)
and [Undefined Behavior Sanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).
This is mostly done automagically by various CI systems for each PR, but you may
want to do it locally as well. The process slightly varies depending on the
compiler you want to use and which part of the test suite you want to run.

## gcc
gcc compiles in sanitizer libraries dynamically by default, so you need to get
the shared libraries first - on Fedora these are shipped as a separate packages
(`libasan` for Address Sanitizer and `libubsan` for Undefined Behavior Sanitizer).

The compilation itself is then a matter of simply adding `-Db_sanitize=address,undefined`
to `meson`. That's it - following executions of `meson test` and integrations tests
under `test/` subdirectory will run with sanitizers enabled. However, to get
truly useful results, you should tweak the runtime configuration of respective
sanitizers; e.g. in systemd we set the following environment variables:

```bash
ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1
UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1
```
## clang
In case of clang things are somewhat different - the sanitizer libraries are
compiled in statically by default. This is not an issue if you plan to run
only the unit tests, but for integration tests you'll need to convince clang
to use the dynamic versions of sanitizer libraries.

First of all, pass `-shared-libsan` to both `clang` and `clang++`:

```bash
CFLAGS=-shared-libasan
CXXFLAGS=-shared-libasan
```

The `CXXFLAGS` are necessary for `src/libsystemd/sd-bus/test-bus-vtable-cc.c`. Compilation
is then the same as in case of gcc, simply add `-Db_sanitize=address,undefined`
to the `meson` call and use the same environment variables for runtime configuration.

```bash
ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1
UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1
```

After this, you'll probably notice that all compiled binaries complain about
missing `libclang_rt.asan*` library. To fix this, you have to install clang's
runtime libraries, usually shipped in the `compiler-rt` package. As these libraries
are installed in a non-standard location (non-standard for `ldconfig`), you'll
need to manually direct binaries to the respective runtime libraries.

```
# Optionally locate the respective runtime DSO
$ ldd build/systemd | grep libclang_rt.asan
        libclang_rt.asan-x86_64.so => not found
        libclang_rt.asan-x86_64.so => not found
$ find /usr/lib* /usr/local/lib* -type f -name libclang_rt.asan-x86_64.so 2>/dev/null
/usr/lib64/clang/7.0.1/lib/libclang_rt.asan-x86_64.so

# Set the LD_LIBRARY_PATH accordingly
export LD_LIBRARY_PATH=/usr/lib64/clang/7.0.1/lib/

# If the path is correct, the "not found" message should change to an actual path
$ ldd build/systemd | grep libclang_rt.asan
        libclang_rt.asan-x86_64.so => /usr/lib64/clang/7.0.1/lib/libclang_rt.asan-x86_64.so (0x00007fa9752fc000)
```

This should help binaries to correctly find necessary sanitizer DSOs.

Also, to make the reports useful, `llvm-symbolizer` tool is required (usually
part of the `llvm` package).

## Background notes
The reason why you need to force dynamic linking in case of `clang` is that some
applications make use of `libsystemd`, which is compiled with sanitizers as well.
However, if a *standard* (uninstrumented) application loads an instrumented library,
it will immediately fail due to unresolved symbols. To fix/workaround this, you
need to pre-load the ASan DSO using `LD_PRELOAD=/path/to/asan/dso`, which will
make things work as expected in most cases. This will, obviously, not work with
statically linked sanitizer libraries.

These shenanigans are performed automatically when running the integration test
suite (i.e. `test/TEST-??-*`) and are located in `test/test-functions` (mainly,
but not only, in the `create_asan_wrapper` function).
