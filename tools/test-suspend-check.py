#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

PLUGIN, ROOT, CLANG_TIDY = sys.argv[1:4]
sys.argv[1:4] = []
HEADER = '#include "src/basic/await.h"\n'
SEED = '_may_suspend_ int pause_io(void);\nint unannotated(void);\n_sync_ int quick(void);\n'
DIAGNOSTIC = re.compile(r'^(.+?):(\d+):\d+: (?:warning|error): (.+) \[systemd-suspend[^\]]*\]$', re.MULTILINE)
ITERATOR = SEED + '''
typedef struct Iterator { unsigned idx; } Iterator;
_sync_ int iterate(void *h, Iterator *i, void **v);
#define FOREACH(v, h) for (Iterator _i = {}; iterate(h, &_i, &(v)); )
'''
EXPECT = re.compile(r'// expect: (.+?)(?= // (?:expect|note): |$)')
NOTE = re.compile(r'^(.+?):(\d+):\d+: note: (.+)$', re.MULTILINE)
EXPECT_NOTE = re.compile(r'// note: (.+?)(?= // (?:expect|note): |$)')


class SuspensionChecks(unittest.TestCase):
    def check(self, sources, args=(), tidy_args=(), fixed=None, notes=False, checks='-*,systemd-suspend'):
        # Every "// expect: <message>" comment must match a diagnostic on its line, and no line may get a
        # diagnostic without one. Only the first file is passed to clang-tidy, the others are headers.
        # "{dir}" in compiler arguments refers to the directory of the sources. When "fixed" is given,
        # the first file must contain that text after clang-tidy applies its fix-its. When "notes" is
        # true, the "// note: <message>" comments must match the notes in the same way.
        with tempfile.TemporaryDirectory(prefix='test-suspend-check-', dir='/var/tmp') as temporary:
            directory = pathlib.Path(temporary)
            expected, expected_notes = set(), set()
            for name, source in sources.items():
                text = HEADER + source
                (directory / name).parent.mkdir(parents=True, exist_ok=True)
                (directory / name).write_text(text)
                for number, line in enumerate(text.splitlines(), start=1):
                    for message in EXPECT.findall(line):
                        expected.add((name, number, message))
                    for message in EXPECT_NOTE.findall(line):
                        expected_notes.add((name, number, message))

            main = directory / next(iter(sources))
            result = subprocess.run(
                [CLANG_TIDY, f'--load={PLUGIN}', f'--checks={checks}', '--header-filter=.*', *tidy_args,
                 str(main), '--', '-std=gnu17', '-I', ROOT, '-I', temporary, *(a.format(dir=temporary) for a in args)],
                text=True, capture_output=True, timeout=60,
            )
            log = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, log)
            actual = {(str(pathlib.Path(path).resolve().relative_to(directory.resolve())), int(line), message)
                      for path, line, message in DIAGNOSTIC.findall(log)}
            self.assertEqual(actual, expected, log)
            if notes:
                actual = {(str(pathlib.Path(path).resolve().relative_to(directory.resolve())), int(line), message)
                          for path, line, message in NOTE.findall(log) if not message.startswith('expanded from macro')}
                self.assertEqual(actual, expected_notes, log)

            if fixed is not None:
                result = subprocess.run(
                    [CLANG_TIDY, f'--load={PLUGIN}', f'--checks={checks}', '--header-filter=.*', '--fix',
                     *tidy_args, str(main), '--', '-std=gnu17', '-I', ROOT, '-I', temporary,
                     *(a.format(dir=temporary) for a in args)],
                    text=True, capture_output=True, timeout=60,
                )
                self.assertEqual(main.read_text(), HEADER + fixed, result.stdout + result.stderr)

    def test_missing_await(self):
        # A fiber-capable function must wrap each call to a _may_suspend_ function in SD_AWAIT(). The same
        # call with the marker gets no diagnostic.
        self.check({'a.c': SEED + '''
_may_suspend_ int run(void) {
        int r = pause_io(); // expect: call to 'pause_io' may suspend; wrap it in SD_AWAIT()
        return r + SD_AWAIT(pause_io());
}
'''})

    def test_synchronous_code(self):
        # Unannotated functions are synchronous code. They can call _may_suspend_ and unchecked
        # functions without markers.
        self.check({'a.c': SEED + '''
int run(void) {
        return pause_io() + unannotated();
}
'''})

    def test_unnecessary_await(self):
        # SD_AWAIT() on a call that cannot suspend is reported in every function, whether the callee is
        # declared _sync_, a system function, or a helper inferred not to suspend.
        self.check({'a.c': SEED + '''
#include <string.h>
static int helper(void) { return 1; }
int run(const char *s) {
        return SD_AWAIT(quick()) + // expect: SD_AWAIT() on a call to 'quick' that cannot suspend
               SD_AWAIT(strlen(s)) + // expect: SD_AWAIT() on a call to 'strlen' that cannot suspend
               SD_AWAIT(helper()); // expect: SD_AWAIT() on a call to 'helper' that cannot suspend
}
'''})

    def test_await_single_call(self):
        # SD_AWAIT() must wrap a call directly. A marker around arithmetic or around the argument of
        # another call doesn't acknowledge the calls inside it.
        self.check({'a.c': SEED + '''
_may_suspend_ int consume(int value);
_may_suspend_ int run(void) {
        int r = SD_AWAIT(pause_io() + 1); // expect: SD_AWAIT() must wrap a single call // expect: call to 'pause_io' may suspend; wrap it in SD_AWAIT()
        return r + SD_AWAIT(consume(pause_io())); // expect: call to 'pause_io' may suspend; wrap it in SD_AWAIT()
}
'''})

    def test_generic_marker(self):
        # A marker in the body of a reusable macro is exempt from the unnecessary-await check, because other
        # expansions of the macro can need it. A marker passed as an argument of another macro is not.
        self.check({'a.c': SEED + '''
#define CALL(f) SD_AWAIT(f())
#define IDENTITY(x) (x)
int run(void) {
        return CALL(quick) +
               IDENTITY(SD_AWAIT(quick())); // expect: SD_AWAIT() on a call to 'quick' that cannot suspend
}
'''})

    def test_unchecked_call(self):
        # A fiber-capable function can't call an unannotated function without a body in the translation
        # unit, because that function can suspend without a marker.
        self.check({'a.c': SEED + '''
_may_suspend_ int run(void) {
        return unannotated(); // expect: unchecked call to 'unannotated' requires a fiber-callable declaration
}
_sync_ int other(void) {
        return unannotated(); // expect: unchecked call to 'unannotated' requires a fiber-callable declaration
}
'''})

    def test_sync_violation(self):
        # A _sync_ function can't call a _may_suspend_ function, even with SD_AWAIT().
        self.check({'a.c': SEED + '''
_sync_ int run(void) {
        return SD_AWAIT(pause_io()); // expect: call to 'pause_io' may suspend in _sync_ function 'run'
}
'''})

    def test_inferred_helpers(self):
        # Unannotated helpers with a body are inferred. Helpers that only call functions that cannot
        # suspend are fiber-callable, also when they call each other recursively. A helper that calls a
        # _may_suspend_ function is unchecked, with or without SD_AWAIT().
        self.check({'a.c': SEED + '''
static int odd(int n);
static int even(int n) { return n == 0 ? quick() : odd(n - 1); }
static int odd(int n) { return n == 0 ? 0 : even(n - 1); }
static int waits(void) { return SD_AWAIT(pause_io()); }
_may_suspend_ int run(void) {
        return even(4) +
               waits(); // expect: unchecked call to 'waits' requires a fiber-callable declaration
}
'''})

    def test_blocking_region(self):
        # SD_BLOCKING() runs its argument synchronously, so neither unchecked nor _may_suspend_
        # calls inside it need anything else, even in a _sync_ function.
        self.check({'a.c': SEED + '''
_sync_ int run(void) {
        return SD_BLOCKING(unannotated()) + SD_BLOCKING(pause_io());
}
'''})

    def test_sync_region(self):
        # Functions that a header declares between SYNC_BEGIN and SYNC_END are _sync_,
        # so fiber code can call them and their bodies are checked. An explicit _may_suspend_ in the
        # region overrides the default.
        self.check({'a.c': '''#include "api.h"
int helper(void) {
        return unannotated(); // expect: unchecked call to 'unannotated' requires a fiber-callable declaration
}
_may_suspend_ int waits(void) {
        return SD_AWAIT(pause_io());
}
_may_suspend_ int run(void) {
        return helper() + SD_AWAIT(waits());
}
''', 'api.h': SEED + '''
SYNC_BEGIN
int helper(void);
_may_suspend_ int waits(void);
SYNC_END
'''})

    def test_trusted_attributes(self):
        # Functions declared pure or const are trusted not to suspend. Their bodies aren't checked.
        self.check({'a.c': SEED + '''
__attribute__((pure)) static int peek(void) { return unannotated(); }
_may_suspend_ int run(void) {
        return peek();
}
'''})

    def test_conflicting_contracts(self):
        # A function can't be both _may_suspend_ and _sync_, also not across redeclarations.
        self.check({'a.c': SEED + '''
_may_suspend_ int both(void);
_sync_ int both(void); // expect: 'both' has conflicting suspension contracts
'''})

    def test_native_callback(self):
        # A system function can invoke its callback arguments before it returns. Passing a callback that
        # isn't _sync_ makes the call unchecked unless it runs in SD_BLOCKING().
        self.check({'a.c': SEED + '''
#include <stdlib.h>
int compare_slow(const void *a, const void *b);
static int compare_fast(const void *a, const void *b) { return 0; }
_may_suspend_ void run(int *values, size_t n) {
        qsort(values, n, sizeof(int), compare_fast);
        qsort(values, n, sizeof(int), compare_slow); // expect: call to 'qsort' passes a callback that can suspend; wrap it in SD_BLOCKING()
        SD_BLOCKING(qsort(values, n, sizeof(int), compare_slow));
}
'''})

    def test_project_definition_of_system_declaration(self):
        # A function that a system header declares but the project defines, like a PAM module entry point,
        # isn't native. Its body is inferred like any other.
        self.check({'a.c': SEED + '''
#include <module.h>
int module_entry(void) { return unannotated(); }
_may_suspend_ int run(void) {
        return module_entry(); // expect: unchecked call to 'module_entry' requires a fiber-callable declaration
}
''', 'include/module.h': 'int module_entry(void);\n'}, args=['-isystem', '{dir}/include'])

    def test_callback_calls(self):
        # A call through a function pointer has the contract of the pointer's declaration and type.
        # Unannotated function pointers are unchecked.
        self.check({'a.c': SEED + '''
typedef int (*fiber_func_t)(void) _may_suspend_;
_may_suspend_ int run(fiber_func_t fiber, int (*plain)(void), int (*quick_cb)(void) _sync_) {
        return SD_AWAIT(fiber()) +
               fiber() + // expect: call to 'fiber' may suspend; wrap it in SD_AWAIT()
               quick_cb() +
               plain(); // expect: unchecked call to 'plain' requires a fiber-callable declaration
}
'''})

    def test_callback_assignment(self):
        # Storing a function pointer checks it against the contract of the destination. An unchecked
        # value can't be stored in a _may_suspend_ slot. A _may_suspend_ value can't be stored in a
        # _sync_ slot. Unannotated slots accept any value.
        self.check({'a.c': SEED + '''
typedef int (*fiber_func_t)(void) _may_suspend_;
fiber_func_t fiber;
int (*quick_cb)(void) _sync_;
int (*plain)(void);
void run(void) {
        fiber = quick;
        fiber = unannotated; // expect: 'unannotated' is unchecked, but 'fiber' requires a _may_suspend_ callback
        quick_cb = pause_io; // expect: 'pause_io' is _may_suspend_, but 'quick_cb' requires a _sync_ callback
        quick_cb = 0;
        plain = pause_io;
        quick_cb = plain; // expect: 'plain' is unchecked, but 'quick_cb' requires a _sync_ callback
}
'''})

    def test_callback_argument(self):
        # A function pointer argument must satisfy the contract of the parameter, also when only the
        # declaration in the header contains the parameter's annotation.
        self.check({'a.c': SEED + '''
#include "api.h"
int register_fiber(int (*callback)(void)) { return 0; }
void run(void) {
        register_fiber(pause_io);
        register_fiber(unannotated); // expect: 'unannotated' is unchecked, but parameter 'callback' of 'register_fiber' requires a _may_suspend_ callback
}
''', 'api.h': 'int register_fiber(int (*callback)(void) _may_suspend_);\n'})

    def test_variadic_callbacks(self):
        # _varargs_may_suspend_(first, stride) declares the variadic arguments at first, first + stride
        # and so on as _may_suspend_ callbacks. The other variadic arguments aren't checked, and a
        # malformed contract gets a diagnostic.
        self.check({'a.c': SEED + '''
int bind_many(void *s, ...) _varargs_may_suspend_(2, 2);
int broken(void *s, ...) _varargs_may_suspend_(0, 2); // expect: 'broken' has an invalid variadic suspension contract
void run(void *s) {
        bind_many(s, "io.systemd.Foo.Bar", pause_io, "io.systemd.Foo.Baz", quick, (void*) 0);
        bind_many(s, "io.systemd.Foo.Bar", unannotated, (void*) 0); // expect: 'unannotated' is unchecked, but argument 2 of 'bind_many' requires a _may_suspend_ callback
}
'''})

    def test_callback_initializer(self):
        # Initializers of structs and arrays check each function pointer against the contract of its
        # field or element type.
        self.check({'a.c': SEED + '''
typedef int (*fiber_func_t)(void) _may_suspend_;
struct Ops {
        int (*quick_cb)(void) _sync_;
        int (*plain)(void);
};
static const struct Ops ops = {
        .quick_cb = pause_io, // expect: 'pause_io' is _may_suspend_, but 'quick_cb' requires a _sync_ callback
        .plain = unannotated,
};
static const fiber_func_t table[] = {
        pause_io,
        unannotated, // expect: 'unannotated' is unchecked, but 'table' requires a _may_suspend_ callback
};
void run(struct Ops *o) {
        *o = (struct Ops) {
                .quick_cb = unannotated, // expect: 'unannotated' is unchecked, but 'quick_cb' requires a _sync_ callback
        };
}
'''})

    def test_callback_return(self):
        # A returned function pointer must satisfy the contract of the return type.
        self.check({'a.c': SEED + '''
typedef int (*quick_func_t)(void) _sync_;
quick_func_t pick(int i) {
        if (i)
                return quick;
        return pause_io; // expect: 'pause_io' is _may_suspend_, but the return value of 'pick' requires a _sync_ callback
}
'''})

    def test_callback_cast(self):
        # A cast to an annotated function pointer type checks its operand. A cast to an unannotated type
        # keeps the contract of its operand. A conversion from a void pointer is trusted.
        self.check({'a.c': SEED + '''
typedef int (*fiber_func_t)(void) _may_suspend_;
typedef int (*plain_func_t)(void);
int (*quick_cb)(void) _sync_;
void run(void *p) {
        fiber_func_t a = (fiber_func_t) unannotated; // expect: 'unannotated' is unchecked, but the cast requires a _may_suspend_ callback
        fiber_func_t b = (fiber_func_t) p;
        fiber_func_t c = (void*) unannotated;
        quick_cb = (plain_func_t) pause_io; // expect: 'pause_io' is _may_suspend_, but 'quick_cb' requires a _sync_ callback
}
'''})

    def test_conditional_value(self):
        # A conditional expression has the weaker contract of its operands.
        self.check({'a.c': SEED + '''
int (*quick_cb)(void) _sync_;
void run(int i) {
        quick_cb = i ? quick : pause_io; // expect: callback is _may_suspend_, but 'quick_cb' requires a _sync_ callback
}
'''})

    def test_unmodified_local(self):
        # A local function pointer that never changes after its initialization has the contract of its
        # initializer. A local that is assigned again, or whose address is passed on, has the contract
        # of its declaration.
        self.check({'a.c': SEED + '''
_sync_ void replace(int (**callback)(void));
_may_suspend_ int run(int i) {
        int (*fixed)(void) = pause_io;
        int (*changing)(void) = pause_io;
        int (*escaping)(void) = pause_io;
        if (i)
                changing = unannotated;
        replace(&escaping);
        return SD_AWAIT(fixed()) +
               SD_AWAIT(changing()) + // expect: unchecked call to 'changing' requires a fiber-callable declaration
               SD_AWAIT(escaping()); // expect: unchecked call to 'escaping' requires a fiber-callable declaration
}
'''})

    def test_scoped_callbacks(self):
        # A call to a function that receives scoped callbacks has the weakest contract of the function
        # and of the callbacks that it receives as arguments, as variadic arguments or in the fields of a
        # table. The function can call the callbacks that it receives, and pass them on, without a
        # contract of its own. A table whose initializer isn't visible at the call makes the call
        # unchecked.
        self.check({'a.c': SEED + '''
typedef int (*visit_t)(int value) _scoped_callback_;
typedef struct Entry { const char *name; visit_t visit; } Entry;
extern const Entry *current;
_sync_ int walk(visit_t visit) { return visit(1); }
_sync_ int walk_table(const Entry table[]) { return table[0].visit(1); }
_sync_ int walk_many(int n, ...);
_sync_ int forward(visit_t visit, const Entry table[]) { return walk(visit) + walk_table(table) + walk_table(table + 1); }
static int quiet(int value) { return value; }
_may_suspend_ int waits(int value) { return SD_AWAIT(pause_io()) + value; }
static int blocks(int value) { return unannotated() + value; }
_may_suspend_ int run(void) {
        static const Entry quiet_table[] = { { "quiet", quiet } };
        static const Entry waiting_table[] = { { "waits", waits } };
        return walk(quiet) +
               SD_AWAIT(walk(waits)) +
               walk(waits) + // expect: call to 'walk' may suspend; wrap it in SD_AWAIT()
               walk(blocks) + // expect: unchecked call to 'walk' requires a fiber-callable declaration
               walk_table(quiet_table) +
               walk_table(&quiet_table[0]) +
               walk_table((void *) 0) +
               SD_AWAIT(walk_table(waiting_table)) +
               walk_table((const Entry[]) { { "blocks", blocks } }) + // expect: unchecked call to 'walk_table' requires a fiber-callable declaration
               walk_table(current) + // expect: unchecked call to 'walk_table' requires a fiber-callable declaration
               walk_many(1, (visit_t) { quiet }) +
               SD_AWAIT(walk_many(1, (visit_t) { waits })) +
               SD_AWAIT(walk(quiet)); // expect: SD_AWAIT() on a call to 'walk' that cannot suspend
}
'''})

        # The notes of an unchecked call point at the scoped callbacks that make it
        # unchecked, and at a table whose callbacks aren't visible.
        self.check({'a.c': '''
typedef int (*visit_t)(int value) _scoped_callback_;
typedef struct Entry { const char *name; visit_t visit; } Entry;
_sync_ int walk_table(const Entry table[]);
int unannotated(void); // note: 'unannotated' is declared here without _may_suspend_ or _sync_
static int blocks(int value) {
        return unannotated() + value; // note: 'blocks' is unchecked because of this call to 'unannotated'
}
extern const Entry *current;
_may_suspend_ int run(void) {
        static const Entry table[] = {
                { "blocks", blocks }, // note: 'blocks' is unchecked and runs during the call to 'walk_table'
        };
        return walk_table(table) + // expect: unchecked call to 'walk_table' requires a fiber-callable declaration
               walk_table(current); // expect: unchecked call to 'walk_table' requires a fiber-callable declaration // note: the callbacks in 'current' are unknown at the call to 'walk_table'
}
'''}, notes=True)

    def test_suspend(self):
        # A _suspend_ function has no synchronous fallback. A call to one is an error in a blocking
        # region and in an unchecked function, unless every path to the call goes through a
        # branch where a _suspend_guard_ function returned true: an if, an early return or an
        # assertion. A function that calls a _suspend_ function without a guard requires a fiber
        # itself, and an exported _may_suspend_ function that requires a fiber has to be declared
        # _suspend_.
        self.check({'a.c': SEED + '''
_suspend_ int wait_fiber(void);
_sync_ int on_fiber(void) _suspend_guard_;
#define check_fiber() do { if (__builtin_expect(!!(!on_fiber()), 0)) __builtin_trap(); } while (0)
_may_suspend_ static int helper(void) { return SD_AWAIT(wait_fiber()); }
_may_suspend_ static int branch(void) {
        if (on_fiber() && quick())
                return SD_AWAIT(wait_fiber());
        return 0;
}
_may_suspend_ static int early(void) {
        if (!on_fiber())
                return 0;
        return SD_AWAIT(wait_fiber());
}
_may_suspend_ static int asserted(void) {
        check_fiber();
        return SD_AWAIT(wait_fiber());
}
_may_suspend_ static int after_branch(void) {
        if (on_fiber())
                quick();
        return SD_AWAIT(wait_fiber());
}
_may_suspend_ int exported(void) { // expect: 'exported' requires a fiber; declare it _suspend_
        return SD_AWAIT(helper());
}
_suspend_ int declared(void) { return SD_AWAIT(helper()); }
int sync_caller(void) {
        if (on_fiber())
                return wait_fiber();
        return wait_fiber(); // expect: call to 'wait_fiber' requires a fiber, but 'sync_caller' is unchecked
}
_may_suspend_ int run(void) {
        return SD_BLOCKING(branch()) +
               SD_BLOCKING(early()) +
               SD_BLOCKING(asserted()) +
               SD_BLOCKING(after_branch()) + // expect: call to 'after_branch' in a blocking region, but 'after_branch' requires a fiber
               SD_BLOCKING(helper()); // expect: call to 'helper' in a blocking region, but 'helper' requires a fiber
}
_suspend_ int run_on_fiber(void) {
        return SD_AWAIT(declared());
}
'''})

        # The notes of a call that requires a fiber follow the calls that make each helper require
        # one.
        self.check({'a.c': '''
_suspend_ int wait_fiber(void);
_may_suspend_ static int inner(void) {
        return SD_AWAIT(wait_fiber()); // note: 'inner' requires a fiber because of this call to 'wait_fiber'
}
_may_suspend_ static int outer(void) {
        return SD_AWAIT(inner()); // note: 'outer' requires a fiber because of this call to 'inner'
}
_may_suspend_ int run(void) {
        return SD_BLOCKING(outer()); // expect: call to 'outer' in a blocking region, but 'outer' requires a fiber
}
'''}, notes=True)

    def test_typeof_library_function(self):
        # DLSYM_PROTOTYPE() declares pointers with the type of a library function. Calls through them are
        # native calls.
        self.check({'a.c': SEED + '''
#include <string.h>
extern typeof(strlen) *sym_strlen;
_may_suspend_ size_t run(const char *s) {
        return sym_strlen(s);
}
'''})

    def test_cleanup(self):
        # A cleanup that can suspend needs _cleanup_await_(), and _cleanup_await_() on a cleanup that
        # cannot suspend is reported.
        self.check({'a.c': SEED + '''
_may_suspend_ void release(int *p);
_sync_ void forget(int *p);
_may_suspend_ int run(void) {
        int a __attribute__((cleanup(release))) = 0; // expect: cleanup 'release' may suspend; declare it with _cleanup_await_()
        int b __attribute__((cleanup(release))) _await_cleanup_ = 0;
        int c __attribute__((cleanup(forget))) _await_cleanup_ = 0; // expect: _cleanup_await_() on cleanup 'forget' that cannot suspend
        return a + b + c;
}
'''})

    def test_cleanup_callback(self):
        # CLEANUP_ARRAY() invokes the destructor from the initializer of its cleanup variable, so the
        # cleanup has the contract of that destructor.
        self.check({'a.c': SEED + '''
#include "src/fundamental/cleanup-util.h"
_may_suspend_ void wait_many(int *array, size_t n);
_sync_ void free_many(int *array, size_t n);
void slow_many(int *array, size_t n);
_may_suspend_ void run(int *a, size_t n) {
        CLEANUP_ARRAY(a, n, free_many);
}
_may_suspend_ void run_wait(int *a, size_t n) {
        CLEANUP_ARRAY(a, n, wait_many); // expect: cleanup 'array_cleanup' may suspend; declare it with _cleanup_await_()
}
_may_suspend_ void run_await(int *a, size_t n) {
        _await_cleanup_ CLEANUP_ARRAY(a, n, wait_many);
}
_may_suspend_ void run_slow(int *a, size_t n) {
        CLEANUP_ARRAY(a, n, slow_many); // expect: unchecked call to 'array_cleanup' requires a fiber-callable declaration
}
'''}, args=['-DRELATIVE_SOURCE_PATH="."'])

    def test_fix_await(self):
        # clang-tidy --fix wraps a call that can suspend in SD_AWAIT() and unwraps an SD_AWAIT() around a
        # call that cannot suspend, also inside the argument of another macro. A macro that expands to
        # exactly the call gets wrapped as a whole. A call that is only part of a macro body gets no
        # fix-it, because the edit would change every expansion of the macro.
        source = SEED + '''
#define IDENTITY(x) (x)
#define CALL() pause_io()
#define TWICE() (pause_io() + 1)
_may_suspend_ int run(void) {
        int r = pause_io(); // expect: call to 'pause_io' may suspend; wrap it in SD_AWAIT()
        r += SD_AWAIT(quick()); // expect: SD_AWAIT() on a call to 'quick' that cannot suspend
        r += IDENTITY(SD_AWAIT(quick())); // expect: SD_AWAIT() on a call to 'quick' that cannot suspend
        r += TWICE(); // expect: call to 'pause_io' may suspend; wrap it in SD_AWAIT()
        return r + CALL(); // expect: call to 'pause_io' may suspend; wrap it in SD_AWAIT()
}
'''
        fixed = (source.replace('int r = pause_io();', 'int r = SD_AWAIT(pause_io());')
                       .replace('r += SD_AWAIT(quick());', 'r += quick();')
                       .replace('IDENTITY(SD_AWAIT(quick()))', 'IDENTITY(quick())')
                       .replace('r + CALL();', 'r + SD_AWAIT(CALL());'))
        self.check({'a.c': source}, fixed=fixed)

    def test_fix_cleanup(self):
        # clang-tidy --fix turns _cleanup_() into _cleanup_await_() for a cleanup that can suspend. It
        # turns _cleanup_await_() back into _cleanup_() for a cleanup that cannot suspend. For a cleanup
        # that CLEANUP_ARRAY() declares, it adds or removes _await_cleanup_ in front of the macro.
        source = SEED + '''
#include "src/fundamental/cleanup-util.h"
_may_suspend_ void release(int *p);
_sync_ void forget(int *p);
_may_suspend_ void wait_many(int *array, size_t n);
_sync_ void free_many(int *array, size_t n);
_may_suspend_ int run(int *a, size_t n, int *b, size_t m) {
        _cleanup_(release) int x = 0; // expect: cleanup 'release' may suspend; declare it with _cleanup_await_()
        _cleanup_await_(forget) int y = 0; // expect: _cleanup_await_() on cleanup 'forget' that cannot suspend
        CLEANUP_ARRAY(a, n, wait_many); // expect: cleanup 'array_cleanup' may suspend; declare it with _cleanup_await_()
        _await_cleanup_ CLEANUP_ARRAY(b, m, free_many); // expect: _cleanup_await_() on cleanup 'array_cleanup' that cannot suspend
        return x + y;
}
'''
        fixed = (source.replace('_cleanup_(release)', '_cleanup_await_(release)')
                       .replace('_cleanup_await_(forget)', '_cleanup_(forget)')
                       .replace('        CLEANUP_ARRAY(a, n, wait_many);', '        _await_cleanup_ CLEANUP_ARRAY(a, n, wait_many);')
                       .replace('_await_cleanup_ CLEANUP_ARRAY(b, m, free_many);', 'CLEANUP_ARRAY(b, m, free_many);'))
        self.check({'a.c': source}, args=['-DRELATIVE_SOURCE_PATH="."'], fixed=fixed)

    def test_notes(self):
        # A diagnostic about an unchecked callee has notes. The notes follow the calls that made
        # inferred helpers unchecked, down to the declaration of a callee or callback without a
        # contract. A diagnostic about a local that never changes names the function that initialized
        # the local.
        self.check({'a.c': '''
_may_suspend_ int pause_io(void);
int unannotated(void); // note: 'unannotated' is declared here without _may_suspend_ or _sync_
int (*quick_cb)(void) _sync_;
static int waits(void) {
        return SD_AWAIT(pause_io()); // note: 'waits' is unchecked because of this call to 'pause_io'
}
static int inner(void) {
        return unannotated(); // note: 'inner' is unchecked because of this call to 'unannotated'
}
static int outer(void) {
        return inner(); // note: 'outer' is unchecked because of this call to 'inner'
}
_may_suspend_ int run(int (*callback)(void)) { // note: 'callback' is declared here without _may_suspend_ or _sync_
        return waits() + // expect: unchecked call to 'waits' requires a fiber-callable declaration
               outer() + // expect: unchecked call to 'outer' requires a fiber-callable declaration
               unannotated() + // expect: unchecked call to 'unannotated' requires a fiber-callable declaration
               callback(); // expect: unchecked call to 'callback' requires a fiber-callable declaration
}
void store(void) {
        int (*local)(void) = unannotated;
        quick_cb = local; // expect: 'unannotated' is unchecked, but 'quick_cb' requires a _sync_ callback
}
'''}, notes=True)

    def test_iterator(self):
        # An iterator that is used after a suspension point in a _may_suspend_ function gets a
        # diagnostic, because another fiber can modify the iterated hashmap meanwhile. A loop that leaves
        # right after the suspension, an iterator that is declared again after it, and functions that
        # aren't _may_suspend_ get none. An iterator that is assigned again after the suspension gets
        # none either.
        self.check({'a.c': ITERATOR + '''
_may_suspend_ void loop(void *h) {
        void *v;
        FOREACH(v, h) // note: the iterator of FOREACH() is declared here
                SD_AWAIT(pause_io()); // expect: the iterator of FOREACH() is used after this suspension point, and another fiber can invalidate it while this fiber is suspended
}
_may_suspend_ int local(void *h) {
        void *v;
        Iterator it = {}; // note: 'it' is declared here
        SD_AWAIT(pause_io()); // expect: 'it' is used after this suspension point, and another fiber can invalidate it while this fiber is suspended
        return iterate(h, &it, &v);
}
_may_suspend_ int reset(void *h) {
        void *v;
        Iterator it = {};
        iterate(h, &it, &v);
        SD_AWAIT(pause_io());
        it = (Iterator) {};
        return iterate(h, &it, &v);
}
_may_suspend_ void leave(void *h) {
        void *v;
        FOREACH(v, h) {
                SD_AWAIT(pause_io());
                break;
        }
}
_may_suspend_ int fresh(void *h) {
        void *v;
        for (;;) {
                SD_AWAIT(pause_io());
                Iterator i = {};
                if (iterate(h, &i, &v))
                        return 0;
        }
}
void synchronous(void *h) {
        void *v;
        FOREACH(v, h)
                pause_io();
}
'''}, checks='-*,systemd-suspend-iterator', notes=True)

    def test_iterator_types(self):
        # The Types option replaces the list of iterator types.
        self.check({'a.c': ITERATOR + '''
typedef struct Cursor { int position; } Cursor;
_sync_ int advance(Cursor *c);
_may_suspend_ void loop(void *h) {
        void *v;
        FOREACH(v, h)
                SD_AWAIT(pause_io());
}
_may_suspend_ int cursor(void) {
        Cursor c = {};
        SD_AWAIT(pause_io()); // expect: 'c' is used after this suspension point, and another fiber can invalidate it while this fiber is suspended
        return advance(&c);
}
'''}, checks='-*,systemd-suspend-iterator',
           tidy_args=['--config={CheckOptions: {systemd-suspend-iterator.Types: Cursor}}'])

    def test_nolint(self):
        # NOLINT suppresses a diagnostic on its line.
        self.check({'a.c': SEED + '''
_may_suspend_ int run(void) {
        return pause_io(); // NOLINT(systemd-suspend)
}
'''})

    def test_header(self):
        # Diagnostics in included project headers are reported when the header filter allows them.
        self.check({'a.c': '#include "api.h"\n', 'api.h': SEED + '''
_may_suspend_ static inline int run(void) {
        return pause_io(); // expect: call to 'pause_io' may suspend; wrap it in SD_AWAIT()
}
'''})

    def test_unevaluated(self):
        # Operands of sizeof, typeof() and _Generic aren't evaluated, so their calls need no markers.
        self.check({'a.c': SEED + '''
_may_suspend_ int run(void) {
        typeof(pause_io()) r = sizeof(pause_io());
        return r + _Generic(0, int: 0, default: pause_io());
}
'''})

    def test_boot(self):
        # Translation units for the boot loader, which define SD_BOOT to 1, are skipped.
        self.check({'a.c': '#define SD_BOOT 1\n' + SEED + '''
_may_suspend_ int run(void) {
        return pause_io();
}
'''})

    def test_other_languages(self):
        # The check only supports C, so C++ and Objective-C inputs are skipped.
        for language in [('c++', '-std=gnu++17'), ('objective-c', '-std=gnu17')]:
            with self.subTest(language=language):
                self.check({'a.c': SEED + '''
_may_suspend_ int run(void) {
        return pause_io();
}
'''}, args=['-x', *language])


if __name__ == '__main__':
    unittest.main()
