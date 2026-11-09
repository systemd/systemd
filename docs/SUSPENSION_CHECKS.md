---
title: Check Fiber Suspension Points
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Check Fiber Suspension Points

Fiber callers use `SD_AWAIT(function(...))` at calls that can suspend. Helpers keep
their ordinary C return types and output parameters. Synchronous callers can use
the same helpers without `SD_AWAIT`. The macro evaluates its argument once and
preserves its result, including `void`. Scheduling and error handling remain the
responsibility of the called function.

The optional checker requires clang-tidy, its development headers and the Clang
and LLVM development libraries from matching releases. The prototype is tested
with version 23. GCC builds can use the macros without enabling the checker.

## Run the checks

Enable the plugin in your existing Meson build directory:

```sh
tine box -- meson configure build -Dsuspend-check=enabled
tine box -- meson test -C build -v suspend-tidy
```

The plugin contains the `systemd-suspend` and `systemd-suspend-iterator` checks.
The `suspend-tidy` test checks their diagnostics. With the plugin
enabled, Meson's `clang-tidy` tests also load it, so the suite of a directory
checks its suspension points as well:

```sh
tine box -- meson test -C build --suite clang-tidy-sysupdate --print-errorlogs
```

To check one source file:

```sh
tine box -- clang-tidy --load=build/tools/libsuspend-tidy.so \
    --checks='-*,systemd-suspend*' --header-filter='.*' \
    -p build src/sysupdate/updatectl.c
```

Add `--fix` to wrap calls that can suspend in `SD_AWAIT`, to add `_cleanup_await_`
to cleanups that can suspend, and to remove markers from calls and cleanups that
cannot suspend. Calls inside the body of a macro get no fix, because the edit would
change every expansion of the macro. Review the result. A fiber can suspend at each
marker that `--fix` adds, so check that the state the function uses stays valid
across the marker.

Include `--header-filter='.*'` to see findings in included project headers.
`NOLINT(systemd-suspend)` suppresses a diagnostic on its line. With clang-tidy
23.1.3, compilation commands that use `-ivfsoverlay` also need the overlay passed
through clang-tidy's `--vfsoverlay` option to find virtual headers.

Each translation unit is checked on its own. Declarations in included headers
supply the contracts of functions defined elsewhere, so include the header that
declares a function both in its implementation and in its callers. Boot, BPF,
C++ and Objective-C translation units are skipped.

## Declare fiber callability

| Declaration | Callers | Body requirements |
| --- | --- | --- |
| `_may_suspend_` | Synchronous code and fibers | Wrap each call that can suspend in `SD_AWAIT`. |
| `_suspend_` | Fibers outside a blocking region | Wrap each call that can suspend in `SD_AWAIT`. |
| `_sync_` | Synchronous code and fibers | Call only functions that cannot suspend, or use `SD_BLOCKING`. |
| Unannotated function with a body in the translation unit | Inferred | A body that can suspend makes the function unchecked. |
| Unannotated function without a body in the translation unit | Synchronous code or `SD_BLOCKING` | None. |

The checker calls a function unchecked when it can't verify where the function
suspends. That's the case for an unannotated function without a body in the
translation unit, and for an inferred helper that calls a function that can
suspend. A fiber can only call an unchecked function in `SD_BLOCKING`.
Ordinary synchronous code needs no annotations or await markers. For a function
used from a fiber, put `_may_suspend_` or `_sync_` at the front of its
declaration, normally in a header. A function definition only accepts the
annotation there. A declaration cannot combine both annotations.

```c
_sync_ int fiber_ops_blocking_begin(void);
```

The checker infers helpers whose bodies are in the same translation unit. A
helper that only calls functions that cannot suspend can be called from a fiber.
A helper that calls a `_may_suspend_` function is unchecked, even if it
wraps the call in `SD_AWAIT`. Declare the helper `_may_suspend_` to call it from a
fiber. A diagnostic about an unchecked helper has a note at the call that
makes the helper unchecked. When that call is to another inferred helper,
the next note shows the call that makes that helper unchecked. The last
note points at the declaration without `_may_suspend_` or `_sync_`.

Declare a function `_suspend_` when it has no synchronous fallback, like
`sd_fiber_sleep()` and `sd_fiber_await()`. A `_suspend_` function is also
`_may_suspend_`, and it aborts when it runs in a blocking region. A function that
calls a `_suspend_` function requires a fiber too, unless a guard protects the
call. A guard is a check that a `_suspend_guard_` function such as
`fiber_can_suspend()` returned true. The checker follows the control flow, so the
guard can be an `if`, an early return or an assertion before the call:

```c
if (fiber_can_suspend() && bus->event == sd_fiber_get_event())
        return SD_AWAIT(bus_call_suspend(bus, _m, usec, reterr_error, ret_reply));
```

The checker reports a call to a function that requires a fiber when the call is
in a blocking region or in an unchecked function. Declare an exported
`_may_suspend_` function that requires a fiber `_suspend_`, because callers in
other files can't see its body. The notes of these diagnostics show the call that
makes each helper require a fiber.

System library functions, compiler builtins and functions declared with the
`pure` or `const` attribute are trusted not to suspend. A function that a system
header declares but the project defines, such as a PAM module entry point, is
inferred like any other.

To declare every function in a header `_sync_`, put `SYNC_BEGIN` after the
includes and `SYNC_END` at the end of the header. `SYNC_BEGIN` must come after
the includes, because the region also covers the functions that included headers
declare. Declare the functions in the region that can suspend `_may_suspend_` or
`_suspend_`, and declare unchecked functions after `SYNC_END`.

Installed systemd headers use `_sd_may_suspend_`, `_sd_suspend_`,
`_sd_sync_`, `_SD_SYNC_BEGIN` and `_SD_SYNC_END`.

## Acknowledge a suspension point

```c
_may_suspend_ static int load_metadata(int fd, void *buffer, size_t size) {
        return SD_AWAIT(loop_read_exact(fd, buffer, size, true));
}

_may_suspend_ static int refresh(void *userdata) {
        char buffer[128];
        int fd = PTR_TO_FD(userdata);

        return SD_AWAIT(load_metadata(fd, buffer, sizeof(buffer)));
}
```

Wrap each call separately. `SD_AWAIT(consume(load_metadata(...)))` acknowledges
`consume()`, so a suspending argument still needs its own marker. `SD_AWAIT`
around arithmetic or a block gets a diagnostic. `SD_AWAIT` around a call that
cannot suspend also gets a diagnostic, in every function. Markers in the body of a
reusable macro, such as `DEFINE_TRIVIAL_CLEANUP_FUNC()`, are exempt, because other
expansions of the macro can need them. Markers passed as arguments of other macros
are checked.

Use `_cleanup_await_(release)` for a cleanup function that can suspend at scope
exit. `_await_cleanup_` acknowledges an existing cleanup declaration when a macro
supplies the cleanup attribute, for example
`_await_cleanup_ CLEANUP_ARRAY(futures, n, sd_future_cancel_wait_unref_array)`.
`CLEANUP_ARRAY()` and `CLEANUP_ELEMENTS()` have the contract of the destructor
passed to them. An annotation before `DEFINE_TRIVIAL_CLEANUP_FUNC(...)` applies to
the generated function, so declare the wrapper of a suspending destructor
`_may_suspend_`.

## Run synchronous code on a fiber

Use `SD_BLOCKING(function(...))` to select the synchronous paths of basic I/O
and process-wait helpers. The calling fiber remains current, and nested regions
restore the previous mode on exit. Bus and QMP calls and the `sd_fiber_*` I/O
functions also select their synchronous implementations in a blocking region. A
`_suspend_` function aborts instead of switching fibers. Blocking regions can
block the event loop and delay cancellation.

Calls inside `SD_BLOCKING` need no markers and can be unchecked, even in a
`_sync_` function. Dispatchers of ordinary callbacks, such as the D-Bus,
Varlink and event loop dispatchers, invoke them in a blocking region, so those
callbacks keep their synchronous behavior when the dispatcher runs on a fiber.

## Declare callback contracts

Function pointers get their contract from their declaration and from the
typedefs that make up their type. Put `_may_suspend_` or `_sync_` after the
declarator of a typedef, a field, a parameter or a variable:

```c
typedef int (*sd_fiber_func_t)(void *userdata) _sd_may_suspend_;

typedef struct FiberOps {
        ssize_t (*read)(int fd, void *buf, size_t count) _may_suspend_;
        bool (*io_blocked)(void) _sync_;
} FiberOps;
```

A call through a `_may_suspend_` pointer needs `SD_AWAIT`. A call through an
unannotated pointer is unchecked. A local function pointer without a
contract has the contract of its initializer, as long as the function never
assigns it again or passes its address on.

The checker checks each function pointer that is assigned, used in an initializer
of a variable, struct or array, passed as an argument, returned, or cast to an
annotated type. A `_may_suspend_` slot accepts functions that are
`_may_suspend_` or cannot suspend. A `_sync_` slot only accepts functions
that cannot suspend. Unannotated slots accept any function. A cast to an
unannotated function pointer type keeps the contract of its operand.

A conversion from a `void *` to a function pointer is trusted. Dispatchers that
keep fiber callbacks in an untyped table use it to restore the contract:

```c
verb_fiber_func_t dispatch = (verb_fiber_func_t) (void*) verb->dispatch;
return SD_AWAIT(dispatch(argc, argv, verb->data, userdata));
```

Register fiber callbacks with `sd_fiber_new()`, `run_main_fiber()`,
`varlink_server_bind_fiber()`, `SD_BUS_METHOD_FIBER()` for D-Bus methods, or the
`VERB_FIBER` flag for verbs. Their callback types are `_may_suspend_`, so the
checker verifies each registration.

A variadic function that takes a callback at every Nth argument declares the
contract of the callbacks with `_varargs_may_suspend_(first, stride)`. Arguments
count from zero, so `_varargs_may_suspend_(2, 2)` covers the arguments 2, 4, 6 and
so on. Each argument at the covered positions must be a fiber-callable function:

```c
int varlink_server_bind_fiber_many_internal(sd_varlink_server *s, ...) _varargs_may_suspend_(2, 2);
```

A system library function can invoke its callback arguments before it returns.
A call that passes a callback which can suspend, or an unchecked callback,
is unchecked. Wrap it in `SD_BLOCKING` when it runs on a fiber, or declare
the callback `_sync_`.

Declare a callback type `_scoped_callback_` when the functions that receive such
a callback only call it before they return, like `sd_json_dispatch()`,
`sd_json_build()` and `proc_cmdline_parse()`:

```c
typedef int (*proc_cmdline_parse_t)(const char *key, const char *value, void *data) _scoped_callback_;
```

A call to a function that receives scoped callbacks has the weakest contract of
the function and of the callbacks. The checker looks for the callbacks in the
arguments, in the variadic arguments, and in tables. A table is an array
parameter of structures with a field of a scoped callback type, like the dispatch
table of `sd_json_dispatch()`. The checker reads the table from the initializer
of the variable or compound literal that the call passes. A table whose
initializer isn't visible at the call, such as a table behind a pointer, makes
the call unchecked.

In fiber code, a call whose callbacks all cannot suspend needs no marker. A
`_may_suspend_` callback makes the call need `SD_AWAIT`, and an unchecked
callback makes the call unchecked. Synchronous code can pass any callback,
so most scoped callbacks need no annotations.

The function that receives scoped callbacks can call them, or pass them on,
without a contract of its own.

## Keep iterators valid across suspension points

While a fiber is suspended, other fibers and event sources run and can add or
remove hashmap entries. A hashmap iterator that the suspended fiber uses again
afterwards can then skip or repeat entries. The `systemd-suspend-iterator` check
reports each `SD_AWAIT` in a `_may_suspend_` function after which a local
`Iterator` can be used again, for example in the body of `HASHMAP_FOREACH()`:

```c
HASHMAP_FOREACH(unit, m->units)
        r = SD_AWAIT(unit_refresh(unit));
```

A loop that leaves with `break` or `return` right after the suspension point is
not reported, and neither is an iterator that the function assigns again after
the suspension point. To fix a report, copy the entries before the loop, take a
reference on each entry, and iterate over the copy.

The `systemd-suspend-iterator.Types` option contains the semicolon-separated
names of the types to check, `Iterator` by default.

## Interpret the result

The result depends on the declared contracts. The checker does not follow
function pointers through `void *`, variadic arguments without
`_varargs_may_suspend_()`, union members with
different contracts, or callback fields of structs that are passed to system
libraries. It does not compare the contracts of callback parameters in nested
function pointer types. Review conversions through `void *`, variadic arguments
and unions by hand.

The check exposes suspension points; callers must still preserve shared-state
invariants across each acknowledged suspension.
