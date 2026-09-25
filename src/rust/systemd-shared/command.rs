// SPDX-License-Identifier: LGPL-2.1-or-later

//! The command line framework of the C programs (`verbs.h`, `options.h`), for programs written in Rust.
//!
//! A C program declares its options with `OPTION()` at the `case` labels of its `parse_argv()`, its verbs with
//! `VERB()` and itself with `COMMAND()`. The macros put `Option` and `Verb` entries into the `SYSTEMD_OPTIONS`
//! and `SYSTEMD_VERBS` linker sections, and the C code in libsystemd-shared parses the command line from those
//! tables, dispatches verbs, prints `--help` and answers `--introspect-cli`. The macros here put the same entries
//! into the same sections, one array per table so that the order is the order in the source, and everything
//! else is that C code: a program written in Rust behaves exactly like one written in C.
//! `test/test-cli-parity.sh` proves it on a pair of twin programs.
//!
//! ```ignore
//! #![no_main]
//!
//! use systemd_shared::command::{Argv, OptionParser, VERB_ANY};
//! use systemd_shared::prelude::*;
//!
//! verbs! {
//!     COMMAND { names: "systemd-foo\0", abstract_: "Frob the foo.", man_pages: "systemd-foo.1\0" },
//!     VERB_DEFAULT_NOARG(verb_status, "status", "Show the status"),
//!     VERB(verb_show, "show", "NAME...", 2, VERB_ANY, 0, "Show some names"),
//!     VERB_COMMON_HELP_AUTO,
//! }
//!
//! fn verb_status(_args: Argv, _data: usize, _userdata: *mut c_void) -> Result<c_int> { Ok(0) }
//! fn verb_show(args: Argv, _data: usize, _userdata: *mut c_void) -> Result<c_int> { Ok(0) }
//!
//! fn parse_argv(opts: &mut OptionParser) -> Result<c_int> {
//!     foreach_option! { opts,
//!         OPTION_COMMON_HELP => return command_print_help!(),
//!         OPTION_COMMON_VERSION => return version(),
//!         OPTION('v', "verbose", None, "Print more") => VERBOSE.store(true, Ordering::Relaxed),
//!         OPTION_COMMON_INTROSPECT_CLI => return introspect_cli!(sys::SD_JSON_FORMAT_OFF),
//!     }
//!     Ok(1)
//! }
//!
//! fn run(argv: Argv) -> Result<()> {
//!     let mut opts = OptionParser::new(&argv);
//!     if parse_argv(&mut opts)? <= 0 {
//!         return Ok(());
//!     }
//!     dispatch_verb!(opts.args(), ptr::null_mut()).map(|_| ())
//! }
//!
//! define_main!(run);
//! ```

use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::mem::{align_of, size_of};
use core::ptr;

use crate::errno::{check, Result};
use crate::sys;

pub use sys::VERB_ANY;

/// One entry of the `SYSTEMD_OPTIONS` section, C's `Option`. Only [`foreach_option!`] creates these.
#[doc(hidden)]
#[repr(C)]
pub struct OptionEntry {
    pub id: c_int,
    pub flags: sys::OptionFlags,
    pub short_code: c_char,
    pub long_code: *const c_char,
    pub metavar: *const c_char,
    pub data: usize,
    pub help: *const c_char,
}

// SAFETY: the entries are immutable tables that only C reads.
unsafe impl Sync for OptionEntry {}

const _: () = assert!(size_of::<OptionEntry>() == size_of::<sys::Option>());
const _: () = assert!(align_of::<OptionEntry>() == align_of::<sys::Option>());

/// One entry of the `SYSTEMD_VERBS` section, C's `Verb` with `data` as a pointer, because a static
/// initializer cannot cast the address of a command description to `uintptr_t`. Only [`verbs!`] creates these.
#[doc(hidden)]
#[repr(C)]
pub struct VerbEntry {
    pub verb: *const c_char,
    pub min_args: c_uint,
    pub max_args: c_uint,
    pub flags: sys::VerbFlags,
    pub dispatch: Option<unsafe extern "C" fn(c_int, *mut *mut c_char, usize, *mut c_void) -> c_int>,
    pub data: *const c_void,
    pub argspec: *const c_char,
    pub help: *const c_char,
}

// SAFETY: the entries are immutable tables that only C reads.
unsafe impl Sync for VerbEntry {}

const _: () = assert!(size_of::<VerbEntry>() == size_of::<sys::Verb>());
const _: () = assert!(align_of::<VerbEntry>() == align_of::<sys::Verb>());

/// C's `CommandDescription`, what `COMMAND` in [`verbs!`] fills in.
#[doc(hidden)]
#[repr(C)]
pub struct CommandDescriptionEntry {
    pub names: *const c_char,
    pub abstract_: *const c_char,
    pub argspec: *const c_char,
    pub footer: *const c_char,
    pub man_pages: *const c_char,
    pub option_namespace: *const c_char,
    pub option_groups: *const c_char,
    pub pager_flags: *const sys::PagerFlags,
    pub flags: sys::CommandFlags,
}

// SAFETY: the entries are immutable tables that only C reads.
unsafe impl Sync for CommandDescriptionEntry {}

const _: () = assert!(size_of::<CommandDescriptionEntry>() == size_of::<sys::CommandDescription>());
const _: () = assert!(align_of::<CommandDescriptionEntry>() == align_of::<sys::CommandDescription>());

impl CommandDescriptionEntry {
    /// All fields unset.
    pub const NONE: CommandDescriptionEntry = CommandDescriptionEntry {
        names: ptr::null(),
        abstract_: ptr::null(),
        argspec: ptr::null(),
        footer: ptr::null(),
        man_pages: ptr::null(),
        option_namespace: ptr::null(),
        option_groups: ptr::null(),
        pager_flags: ptr::null(),
        flags: 0,
    };
}

/// An `argc`/`argv` pair: what the program was started with, or the positional arguments left after option
/// parsing, or what a verb is dispatched with. `argv[0]` is the program or the verb, as in C.
#[derive(Clone, Copy)]
pub struct Argv {
    argc: c_int,
    argv: *mut *mut c_char,
}

impl Argv {
    /// Wraps a NULL-terminated argument vector.
    ///
    /// # Safety
    ///
    /// `argv` must point to `argc` valid C strings followed by NULL, alive for as long as the value is used.
    pub unsafe fn from_raw(argc: c_int, argv: *mut *mut c_char) -> Argv {
        Argv { argc, argv }
    }

    /// `argc`.
    pub fn len(&self) -> usize {
        usize::try_from(self.argc).unwrap_or(0)
    }

    /// Whether there are no arguments at all (not even `argv[0]`).
    pub fn is_empty(&self) -> bool {
        self.argc <= 0
    }

    /// `argv[i]`.
    pub fn get(&self, i: usize) -> Option<&CStr> {
        if i >= self.len() {
            return None;
        }
        // SAFETY: i < argc, and the entries are valid C strings (from_raw()).
        Some(unsafe { CStr::from_ptr(*self.argv.add(i)) })
    }

    /// The arguments in order.
    pub fn iter(&self) -> impl Iterator<Item = &CStr> + '_ {
        (0..self.len()).filter_map(move |i| self.get(i))
    }

    /// `argc` and `argv`, for passing to C.
    pub fn as_raw(&self) -> (c_int, *mut *mut c_char) {
        (self.argc, self.argv)
    }
}

/// C's `OptionParser`, driven by [`foreach_option!`].
pub struct OptionParser {
    inner: sys::OptionParser,
}

impl OptionParser {
    /// `OptionParser opts = { argc, argv };`
    pub fn new(argv: &Argv) -> OptionParser {
        OptionParser::with_mode(argv, sys::OPTION_PARSER_NORMAL)
    }

    /// `OptionParser opts = { argc, argv, mode };`
    pub fn with_mode(argv: &Argv, mode: sys::OptionParserMode) -> OptionParser {
        let mut inner = sys::OptionParser::default();
        (inner.argc, inner.argv) = argv.as_raw();
        inner.mode = mode;
        OptionParser { inner }
    }

    /// Backend of [`foreach_option!`]: the next option's id, 0 when parsing is done.
    ///
    /// # Safety
    ///
    /// `options` and `options_end` must be the bounds of the `SYSTEMD_OPTIONS` section of the program.
    #[doc(hidden)]
    pub unsafe fn __next(
        &mut self,
        options: *const OptionEntry,
        options_end: *const OptionEntry,
    ) -> Result<c_int> {
        // SAFETY: the caller passes the section bounds, the parser state is ours.
        check(unsafe { sys::option_parse(options.cast(), options_end.cast(), &mut self.inner) })
    }

    /// The argument of the option just returned, `opts.arg` in C; `None` for an option without one.
    pub fn arg(&self) -> Option<&CStr> {
        if self.inner.arg.is_null() {
            return None;
        }
        // SAFETY: the parser points arg at an argv element or NULL.
        Some(unsafe { CStr::from_ptr(self.inner.arg) })
    }

    /// The positional arguments left after parsing, `option_parser_get_args()`.
    pub fn args(&self) -> Argv {
        // SAFETY: plain calls on the parser state; the pointer is into argv, which is NULL-terminated.
        unsafe {
            Argv::from_raw(
                c_int::try_from(sys::option_parser_get_n_args(&self.inner)).unwrap_or(c_int::MAX),
                sys::option_parser_get_args(&self.inner),
            )
        }
    }

    /// `option_parser_get_n_args()`.
    pub fn n_args(&self) -> usize {
        // SAFETY: plain call on the parser state.
        unsafe { sys::option_parser_get_n_args(&self.inner) }
    }
}

/// `version()`: prints the version and the feature string. Evaluates to `Ok(0)`, so that
/// `return version()` in `parse_argv()` reads like C.
pub fn version() -> Result<c_int> {
    // SAFETY: plain call into libsystemd-shared.
    check(unsafe { sys::version() })
}

/// Backend of [`dispatch_verb!`].
///
/// # Safety
///
/// `verbs` and `verbs_end` must be the bounds of the `SYSTEMD_VERBS` section of the program.
#[doc(hidden)]
pub unsafe fn __dispatch_verb(
    args: Argv,
    verbs: *const VerbEntry,
    verbs_end: *const VerbEntry,
    userdata: *mut c_void,
) -> Result<c_int> {
    let (_, argv) = args.as_raw();
    // SAFETY: the caller passes the section bounds, argv is NULL-terminated.
    check(unsafe { sys::_dispatch_verb(argv, verbs.cast(), verbs_end.cast(), userdata) })
}

/// Backend of [`command_print_help!`].
///
/// # Safety
///
/// The four pointers must be the bounds of the `SYSTEMD_VERBS` and `SYSTEMD_OPTIONS` sections of the program.
#[doc(hidden)]
pub unsafe fn __command_print_help(
    verbs: *const VerbEntry,
    verbs_end: *const VerbEntry,
    options: *const OptionEntry,
    options_end: *const OptionEntry,
    name: *const c_char,
) -> Result<c_int> {
    // SAFETY: the caller passes the section bounds, name is NULL or a C string.
    check(unsafe {
        sys::_command_print_help_full(
            verbs.cast(),
            verbs_end.cast(),
            options.cast(),
            options_end.cast(),
            name,
            ptr::null(),
        )
    })
}

/// Backend of [`introspect_cli!`].
///
/// # Safety
///
/// The four pointers must be the bounds of the `SYSTEMD_VERBS` and `SYSTEMD_OPTIONS` sections of the program.
#[doc(hidden)]
pub unsafe fn __introspect_cli(
    verbs: *const VerbEntry,
    verbs_end: *const VerbEntry,
    options: *const OptionEntry,
    options_end: *const OptionEntry,
    flags: sys::sd_json_format_flags_t,
) -> Result<c_int> {
    // SAFETY: the caller passes the section bounds.
    check(unsafe {
        sys::_introspect_cli(
            verbs.cast(),
            verbs_end.cast(),
            options.cast(),
            options_end.cast(),
            flags,
        )
    })
}

/// A string literal as a C string pointer, `None` as NULL. Backend of the table macros.
#[doc(hidden)]
#[macro_export]
macro_rules! __cstr_or_null {
    (None) => {
        ::core::ptr::null()
    };
    ($s:literal) => {
        ::core::concat!($s, "\0").as_ptr().cast::<::core::ffi::c_char>()
    };
}

/// A short option character as `char` in C, 0 for none. Backend of the table macros.
#[doc(hidden)]
#[macro_export]
macro_rules! __short_code {
    (0) => {
        0
    };
    ($c:literal) => {
        ($c as u8) as ::core::ffi::c_char
    };
}

/// One `Option` entry, `OPTION()` and friends from options.h. Backend of [`foreach_option!`].
#[doc(hidden)]
#[macro_export]
macro_rules! __option_entry {
    (($id:expr), OPTION_FULL_DATA($fl:expr, $sc:tt, $lc:tt, $mv:tt, $d:expr, $h:tt)) => {
        $crate::command::OptionEntry {
            id: 0x100 + ($id),
            flags: $fl,
            short_code: $crate::__short_code!($sc),
            long_code: $crate::__cstr_or_null!($lc),
            metavar: $crate::__cstr_or_null!($mv),
            data: $d,
            help: $crate::__cstr_or_null!($h),
        }
    };
    (($id:expr), OPTION_FULL($fl:expr, $sc:tt, $lc:tt, $mv:tt, $h:tt)) => {
        $crate::__option_entry!(($id), OPTION_FULL_DATA($fl, $sc, $lc, $mv, 0, $h))
    };
    (($id:expr), OPTION($sc:tt, $lc:tt, $mv:tt, $h:tt)) => {
        $crate::__option_entry!(($id), OPTION_FULL(0, $sc, $lc, $mv, $h))
    };
    (($id:expr), OPTION_LONG($lc:tt, $mv:tt, $h:tt)) => {
        $crate::__option_entry!(($id), OPTION(0, $lc, $mv, $h))
    };
    (($id:expr), OPTION_LONG_FLAGS($fl:expr, $lc:tt, $mv:tt, $h:tt)) => {
        $crate::__option_entry!(($id), OPTION_FULL($fl, 0, $lc, $mv, $h))
    };
    (($id:expr), OPTION_LONG_DATA($lc:tt, $mv:tt, $d:expr, $h:tt)) => {
        $crate::__option_entry!(($id), OPTION_FULL_DATA(0, 0, $lc, $mv, $d, $h))
    };
    (($id:expr), OPTION_SHORT($sc:tt, $mv:tt, $h:tt)) => {
        $crate::__option_entry!(($id), OPTION($sc, None, $mv, $h))
    };
    (($id:expr), OPTION_SHORT_FLAGS($fl:expr, $sc:tt, $mv:tt, $h:tt)) => {
        $crate::__option_entry!(($id), OPTION_FULL($fl, $sc, None, $mv, $h))
    };
    (($id:expr), OPTION_GROUP($gr:tt)) => {
        $crate::__option_entry!(
            ($id),
            OPTION_FULL($crate::sys::OPTION_GROUP_MARKER, 0, $gr, None, None)
        )
    };
    (($id:expr), OPTION_NAMESPACE($ns:tt)) => {
        $crate::__option_entry!(
            ($id),
            OPTION_FULL($crate::sys::OPTION_NAMESPACE_MARKER, 0, $ns, None, None)
        )
    };
    (($id:expr), OPTION_HELP_VERBATIM($lc:tt, $h:tt)) => {
        $crate::__option_entry!(
            ($id),
            OPTION_FULL($crate::sys::OPTION_HELP_ENTRY_VERBATIM, 0, $lc, None, $h)
        )
    };
    (($id:expr), OPTION_COMMON_HELP) => {
        $crate::__option_entry!(($id), OPTION('h', "help", None, "Show this help"))
    };
    (($id:expr), OPTION_COMMON_VERSION) => {
        $crate::__option_entry!(($id), OPTION_LONG("version", None, "Show package version"))
    };
    (($id:expr), OPTION_COMMON_INTROSPECT_CLI) => {
        $crate::__option_entry!(($id), OPTION_LONG("introspect-cli", None, None))
    };
    (($id:expr), OPTION_COMMON_NO_PAGER) => {
        $crate::__option_entry!(($id), OPTION_LONG("no-pager", None, "Do not start a pager"))
    };
    (($id:expr), OPTION_COMMON_NO_LEGEND) => {
        $crate::__option_entry!(
            ($id),
            OPTION_LONG("no-legend", None, "Do not show headers and footers")
        )
    };
    (($id:expr), OPTION_COMMON_JSON) => {
        $crate::__option_entry!(
            ($id),
            OPTION_LONG("json", "FORMAT", "Generate JSON output (pretty, short, or off)")
        )
    };
    (($id:expr), OPTION_COMMON_LOWERCASE_J) => {
        $crate::__option_entry!(
            ($id),
            OPTION_SHORT(
                'j',
                None,
                "Equivalent to --json=pretty (on TTY) or --json=short (otherwise)"
            )
        )
    };
    (($id:expr), OPTION_COMMON_NO_ASK_PASSWORD) => {
        $crate::__option_entry!(
            ($id),
            OPTION_LONG("no-ask-password", None, "Do not prompt for password")
        )
    };
    (($id:expr), OPTION_COMMON_HOST) => {
        $crate::__option_entry!(
            ($id),
            OPTION('H', "host", "[USER@]HOST", "Operate on remote host")
        )
    };
    (($id:expr), OPTION_COMMON_MACHINE) => {
        $crate::__option_entry!(
            ($id),
            OPTION('M', "machine", "CONTAINER", "Operate on local container")
        )
    };
    (($id:expr), OPTION_COMMON_SYSTEM) => {
        $crate::__option_entry!(($id), OPTION_LONG("system", None, "Operate in system mode"))
    };
    (($id:expr), OPTION_COMMON_USER) => {
        $crate::__option_entry!(($id), OPTION_LONG("user", None, "Operate in per-user mode"))
    };
    (($id:expr), OPTION_COMMON_LOG_LEVEL) => {
        $crate::__option_entry!(
            ($id),
            OPTION_LONG(
                "log-level",
                "LEVEL",
                "Set log level (debug, info, notice, warning, err, crit, alert, emerg)"
            )
        )
    };
    (($id:expr), OPTION_COMMON_LOG_TARGET) => {
        $crate::__option_entry!(
            ($id),
            OPTION_LONG(
                "log-target",
                "TARGET",
                "Set log target (console, journal, journal-or-kmsg, kmsg, null)"
            )
        )
    };
    (($id:expr), OPTION_COMMON_LOG_COLOR) => {
        $crate::__option_entry!(
            ($id),
            OPTION_LONG("log-color", "BOOL", "Highlight important messages")
        )
    };
    (($id:expr), OPTION_COMMON_LOG_LOCATION) => {
        $crate::__option_entry!(
            ($id),
            OPTION_LONG("log-location", "BOOL", "Include code location in messages")
        )
    };
    (($id:expr), OPTION_COMMON_LOG_TIME) => {
        $crate::__option_entry!(
            ($id),
            OPTION_LONG("log-time", "BOOL", "Prefix messages with current time")
        )
    };
}

/// `FOREACH_OPTION_OR_RETURN()` with the `OPTION()` declarations at the arms, as in C:
///
/// ```ignore
/// foreach_option! { opts,
///     OPTION_COMMON_HELP => return command_print_help!(),
///     OPTION_COMMON_VERSION => return version(),
///     OPTION('v', "verbose", None, "Print more") => arg_verbose = true,
///     OPTION('f', "frob", "VALUE", "Set the frob value") => arg_frob = opts.arg(),
///     OPTION_GROUP("Rarely used options") => {},
///     OPTION_COMMON_INTROSPECT_CLI => return introspect_cli!(sys::SD_JSON_FORMAT_OFF),
/// }
/// ```
///
/// The arms are the program's `SYSTEMD_OPTIONS` table, in this order; each is an `OPTION*` form from
/// options.h with `None` for a NULL string. Parse errors are returned from the enclosing function.
#[macro_export]
macro_rules! foreach_option {
    ($opts:ident, $($rest:tt)*) => {
        $crate::__foreach_option!(@go $opts [] [] (0) $($rest)*)
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __foreach_option {
    (@go $opts:ident [$($entry:expr,)*] [$($arm:tt)*] ($i:expr)
     $kind:ident $(( $($a:tt)* ))? => $body:expr $(, $($rest:tt)*)?) => {
        $crate::__foreach_option!(@go $opts
            [$($entry,)* $crate::__option_entry!(($i), $kind $(($($a)*))?),]
            [$($arm)* __c if __c == 0x100 + ($i) => { $body; }]
            ($i + 1)
            $($($rest)*)?)
    };
    (@go $opts:ident [$($entry:expr,)*] [$($arm:tt)*] ($n:expr)) => {{
        #[used]
        #[link_section = "SYSTEMD_OPTIONS"]
        static __OPTIONS: [$crate::command::OptionEntry; $n] = [$($entry,)*];

        extern "C" {
            static __start_SYSTEMD_OPTIONS: $crate::command::OptionEntry;
            static __stop_SYSTEMD_OPTIONS: $crate::command::OptionEntry;
        }

        loop {
            // SAFETY: the linker defines the bounds of the section the table above lives in.
            let __c = unsafe {
                $opts.__next(
                    ::core::ptr::addr_of!(__start_SYSTEMD_OPTIONS),
                    ::core::ptr::addr_of!(__stop_SYSTEMD_OPTIONS),
                )
            }?;
            if __c == 0 {
                break;
            }
            match __c {
                $($arm)*
                _ => ::core::unreachable!("option id not in the table"),
            }
        }
    }};
}

/// One field of a `COMMAND` description. Backend of [`verbs!`].
#[doc(hidden)]
#[macro_export]
macro_rules! __command_field {
    (pager_flags, $v:ident) => {
        $v.as_ptr().cast_const().cast()
    };
    (flags, $v:tt) => {
        $v
    };
    ($other:ident, $v:tt) => {
        $crate::__cstr_or_null!($v)
    };
}

/// One `Verb` entry, `VERB()` and friends from verbs.h. Backend of [`verbs!`].
#[doc(hidden)]
#[macro_export]
macro_rules! __verb_entry {
    (COMMAND { $($field:ident : $value:tt),* $(,)? }) => {
        $crate::command::VerbEntry {
            verb: ::core::ptr::null(),
            min_args: 0,
            max_args: 0,
            flags: $crate::sys::VERB_COMMAND_MARKER,
            dispatch: None,
            data: {
                static __DESCRIPTION: $crate::command::CommandDescriptionEntry =
                    $crate::command::CommandDescriptionEntry {
                        $($field: $crate::__command_field!($field, $value),)*
                        ..$crate::command::CommandDescriptionEntry::NONE
                    };
                ::core::ptr::addr_of!(__DESCRIPTION).cast()
            },
            argspec: ::core::ptr::null(),
            help: ::core::ptr::null(),
        }
    };
    (VERB_FULL($d:path, $v:tt, $a:tt, $amin:expr, $amax:expr, $f:expr, $dat:expr, $h:tt)) => {
        $crate::command::VerbEntry {
            verb: $crate::__cstr_or_null!($v),
            min_args: $amin,
            max_args: $amax,
            flags: $f,
            dispatch: {
                /// The C-callable side of the verb.
                ///
                /// # Safety
                ///
                /// Only `_dispatch_verb()` calls this, with the verb's arguments.
                unsafe extern "C" fn __dispatch(
                    argc: ::core::ffi::c_int,
                    argv: *mut *mut ::core::ffi::c_char,
                    data: usize,
                    userdata: *mut ::core::ffi::c_void,
                ) -> ::core::ffi::c_int {
                    // SAFETY: _dispatch_verb() hands over a NULL-terminated argument vector.
                    let args = unsafe { $crate::command::Argv::from_raw(argc, argv) };
                    $crate::from_result(|| $d(args, data, userdata))
                }
                Some(__dispatch)
            },
            data: ($dat) as *const ::core::ffi::c_void,
            argspec: $crate::__cstr_or_null!($a),
            help: $crate::__cstr_or_null!($h),
        }
    };
    (VERB($d:path, $v:tt, $a:tt, $amin:expr, $amax:expr, $f:expr, $h:tt)) => {
        $crate::__verb_entry!(VERB_FULL($d, $v, $a, $amin, $amax, $f, 0, $h))
    };
    (VERB_NOARG($d:path, $v:tt, $h:tt)) => {
        $crate::__verb_entry!(VERB($d, $v, None, $crate::command::VERB_ANY, 1, 0, $h))
    };
    (VERB_DEFAULT_NOARG($d:path, $v:tt, $h:tt)) => {
        $crate::__verb_entry!(VERB($d, $v, None, $crate::command::VERB_ANY, 1, $crate::sys::VERB_DEFAULT, $h))
    };
    (VERB_GROUP($gr:tt)) => {
        $crate::command::VerbEntry {
            verb: $crate::__cstr_or_null!($gr),
            min_args: 0,
            max_args: 0,
            flags: $crate::sys::VERB_GROUP_MARKER,
            dispatch: None,
            data: ::core::ptr::null(),
            argspec: ::core::ptr::null(),
            help: ::core::ptr::null(),
        }
    };
    (VERB_COMMON_HELP_AUTO) => {
        $crate::__verb_entry!(VERB_COMMON_HELP_AUTO_FULL("Show this help"))
    };
    (VERB_COMMON_HELP_AUTO_HIDDEN) => {
        $crate::__verb_entry!(VERB_COMMON_HELP_AUTO_FULL(None))
    };
    (VERB_COMMON_HELP_AUTO_FULL($h:tt)) => {
        $crate::command::VerbEntry {
            verb: $crate::__cstr_or_null!("help"),
            min_args: $crate::command::VERB_ANY,
            max_args: $crate::command::VERB_ANY,
            flags: 0,
            dispatch: {
                /// `verb_help_auto()` from verbs.h.
                ///
                /// # Safety
                ///
                /// Only `_dispatch_verb()` calls this.
                unsafe extern "C" fn __help(
                    _argc: ::core::ffi::c_int,
                    _argv: *mut *mut ::core::ffi::c_char,
                    data: usize,
                    _userdata: *mut ::core::ffi::c_void,
                ) -> ::core::ffi::c_int {
                    $crate::from_result(|| $crate::command_print_help_name!(data as *const ::core::ffi::c_char))
                }
                Some(__help)
            },
            data: ::core::ptr::null(),
            argspec: ::core::ptr::null(),
            help: $crate::__cstr_or_null!($h),
        }
    };
}

/// The program's `SYSTEMD_VERBS` table: `COMMAND`, `VERB*` and `VERB_GROUP` from verbs.h, in this order.
/// A verb is a `fn(Argv, usize, *mut c_void) -> Result<c_int>`; the `COMMAND` fields are those of
/// `CommandDescription` (`abstract_` for `abstract`), `names` and `man_pages` are nulstrs written like in C,
/// `pager_flags` names a `static AtomicU32`.
#[macro_export]
macro_rules! verbs {
    ($($rest:tt)*) => {
        $crate::__verbs!(@go [] (0) $($rest)*);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __verbs {
    (@go [$($entry:expr,)*] ($i:expr) $kind:ident $(( $($a:tt)* ))? $({ $($f:tt)* })? $(, $($rest:tt)*)?) => {
        $crate::__verbs! { @go [$($entry,)* $crate::__verb_entry!($kind $(($($a)*))? $({ $($f)* })?),] ($i + 1) $($($rest)*)? }
    };
    (@go [$($entry:expr,)*] ($n:expr)) => {
        #[used]
        #[link_section = "SYSTEMD_VERBS"]
        static __VERBS: [$crate::command::VerbEntry; $n] = [$($entry,)*];
    };
}

/// `dispatch_verb(args, userdata)`: runs the verb named by `args[0]` (or the default one).
#[macro_export]
macro_rules! dispatch_verb {
    ($args:expr, $userdata:expr) => {{
        extern "C" {
            static __start_SYSTEMD_VERBS: $crate::command::VerbEntry;
            static __stop_SYSTEMD_VERBS: $crate::command::VerbEntry;
        }
        // SAFETY: the linker defines the bounds of the section the verbs! table lives in.
        unsafe {
            $crate::command::__dispatch_verb(
                $args,
                ::core::ptr::addr_of!(__start_SYSTEMD_VERBS),
                ::core::ptr::addr_of!(__stop_SYSTEMD_VERBS),
                $userdata,
            )
        }
    }};
}

/// `command_print_help_name(name)`: prints `--help` for the command called `name` (NULL: the program).
#[macro_export]
macro_rules! command_print_help_name {
    ($name:expr) => {{
        extern "C" {
            static __start_SYSTEMD_VERBS: $crate::command::VerbEntry;
            static __stop_SYSTEMD_VERBS: $crate::command::VerbEntry;
            static __start_SYSTEMD_OPTIONS: $crate::command::OptionEntry;
            static __stop_SYSTEMD_OPTIONS: $crate::command::OptionEntry;
        }
        // SAFETY: the linker defines the bounds of the sections the tables live in.
        unsafe {
            $crate::command::__command_print_help(
                ::core::ptr::addr_of!(__start_SYSTEMD_VERBS),
                ::core::ptr::addr_of!(__stop_SYSTEMD_VERBS),
                ::core::ptr::addr_of!(__start_SYSTEMD_OPTIONS),
                ::core::ptr::addr_of!(__stop_SYSTEMD_OPTIONS),
                $name,
            )
        }
    }};
}

/// `command_print_help()`: prints `--help`. Evaluates to `Ok(0)`, so that `return command_print_help!()`
/// in `parse_argv()` reads like C.
#[macro_export]
macro_rules! command_print_help {
    () => {
        $crate::command_print_help_name!(::core::ptr::null())
    };
}

/// `introspect_cli(flags)`: answers `--introspect-cli`.
#[macro_export]
macro_rules! introspect_cli {
    ($flags:expr) => {{
        extern "C" {
            static __start_SYSTEMD_VERBS: $crate::command::VerbEntry;
            static __stop_SYSTEMD_VERBS: $crate::command::VerbEntry;
            static __start_SYSTEMD_OPTIONS: $crate::command::OptionEntry;
            static __stop_SYSTEMD_OPTIONS: $crate::command::OptionEntry;
        }
        // SAFETY: the linker defines the bounds of the sections the tables live in.
        unsafe {
            $crate::command::__introspect_cli(
                ::core::ptr::addr_of!(__start_SYSTEMD_VERBS),
                ::core::ptr::addr_of!(__stop_SYSTEMD_VERBS),
                ::core::ptr::addr_of!(__start_SYSTEMD_OPTIONS),
                ::core::ptr::addr_of!(__stop_SYSTEMD_OPTIONS),
                $flags,
            )
        }
    }};
}
