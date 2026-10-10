// SPDX-License-Identifier: LGPL-2.1-or-later

//! The Rust half of the command line parity test: the same command, options and verbs as test-cli-c.c,
//! declared with the macros of `systemd_shared::command`. test/test-cli-parity.sh runs both with the same
//! arguments and expects the same output and exit status, byte for byte.

#![no_std]
#![no_main]

use core::ffi::{c_int, c_void, CStr};
use core::ptr;
use core::sync::atomic::Ordering;

use systemd_shared::cstr::{self, display};
use systemd_shared::prelude::*;
use systemd_shared::{json, sys};

/// What --no-pager sets; the command description points at it.
static ARG_PAGER_FLAGS: AtomicPagerFlags = AtomicPagerFlags::new(0);

/// What the options set, handed to the verbs as their userdata. The strings point into argv, like in C.
struct State<'a> {
    verbose: bool,
    frob: Option<&'a CStr>,
    plumb: Option<&'a CStr>,
    legend: bool,
    json_format_flags: sys::sd_json_format_flags_t,
}

verbs! {
    COMMAND {
        names: "test-cli\0",
        abstract_: "Exercise the command line framework, to compare a C program with its Rust twin.",
        footer: "Both twins print this footer.",
        man_pages: "systemd.1\0",
        pager_flags: ARG_PAGER_FLAGS,
    },
    VERB_DEFAULT_NOARG(verb_status, "status", "Print the parsed options"),
    VERB(verb_show, "show", "NAME [NAME]\0", 2, 3, 0, "Print one or two names"),
    VERB_GROUP("Other commands"),
    VERB_NS_FULL(verb_fail, "fail", None, None, VERB_ANY, 1, 0, 0, "Fail with EIO", "This verb never succeeds."),
    VERB_COMMON_HELP_AUTO(),
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn strna(s: Option<&CStr>) -> cstr::Display<'_> {
    display(s.unwrap_or(c"n/a"))
}

fn print_state(verb: &str, args: Argv<'_>, userdata: *mut c_void) -> Result<c_int> {
    // SAFETY: run() passes its State as the userdata of dispatch_verb!(), and it outlives the dispatch.
    let state = unsafe { &*userdata.cast::<State<'_>>() };
    print!(
        "verb={} verbose={} frob={} plumb={} legend={} json={} args=",
        verb,
        yes_no(state.verbose),
        strna(state.frob),
        strna(state.plumb),
        yes_no(state.legend),
        yes_no(json::format_enabled(state.json_format_flags)),
    );
    for (i, a) in args.iter().skip(1).enumerate() {
        print!("{}{}", if i > 0 { "," } else { "" }, display(a));
    }
    println!();
    Ok(0)
}

fn verb_status(args: Argv<'_>, _data: usize, userdata: *mut c_void) -> Result<c_int> {
    print_state("status", args, userdata)
}

fn verb_show(args: Argv<'_>, _data: usize, userdata: *mut c_void) -> Result<c_int> {
    print_state("show", args, userdata)
}

fn verb_fail(_args: Argv<'_>, _data: usize, _userdata: *mut c_void) -> Result<c_int> {
    Err(log_error_errno!(SYNTHETIC_ERRNO(EIO), "Failing on request."))
}

fn parse_argv<'a>(opts: &mut OptionParser<'a>, state: &mut State<'a>) -> Result<c_int> {
    foreach_option! { opts,
        OPTION_COMMON_HELP => return command_print_help!(),
        OPTION_COMMON_VERSION => return version(),
        OPTION_COMMON_NO_PAGER => ARG_PAGER_FLAGS.fetch_or(sys::PAGER_DISABLE, Ordering::Relaxed),
        OPTION_COMMON_NO_LEGEND => state.legend = false,
        OPTION_COMMON_JSON => {
            let r = json::parse_argument(opts.arg(), &mut state.json_format_flags)?;
            if r <= 0 {
                return Ok(r);
            }
        },
        OPTION_COMMON_LOWERCASE_J => {
            state.json_format_flags = sys::SD_JSON_FORMAT_PRETTY_AUTO | sys::SD_JSON_FORMAT_COLOR_AUTO;
        },
        OPTION('v', "verbose", None, "Print more") => state.verbose = true,
        OPTION('f', "frob", "VALUE", "Set the frob value") => state.frob = opts.arg(),
        OPTION_GROUP("Rarely used options") => {},
        OPTION_LONG_FLAGS(sys::OPTION_OPTIONAL_ARG, "plumb", "LEVEL", "Set the plumbing level") => {
            state.plumb = Some(opts.arg().unwrap_or(c"default"));
        },
        OPTION_COMMON_INTROSPECT_CLI => return introspect_cli!(state.json_format_flags),
    }

    Ok(1)
}

fn run(argv: Argv<'_>) -> Result<()> {
    let mut state = State {
        verbose: false,
        frob: None,
        plumb: None,
        legend: true,
        json_format_flags: sys::SD_JSON_FORMAT_OFF,
    };

    let mut opts = OptionParser::new(argv);
    if parse_argv(&mut opts, &mut state)? <= 0 {
        return Ok(());
    }

    dispatch_verb!(opts.args(), ptr::from_mut(&mut state).cast::<c_void>()).map(|_| ())
}

define_main!(run);
