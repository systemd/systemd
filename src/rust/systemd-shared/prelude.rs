// SPDX-License-Identifier: LGPL-2.1-or-later

//! `use systemd_shared::prelude::*;` brings in what every program needs, including the [`Box`] and [`Vec`]
//! that replace the ones of `alloc`.

pub use crate::alloc::{AllocError, Box, Vec};
pub use crate::command::{version, version_only, Argv, AtomicPagerFlags, OptionParser, VERB_ANY};
pub use crate::cstr::OwnedCStr;
pub use crate::errno::{check, from_result, Errno, Result};
pub use crate::event::{Event, EventSource};
pub use crate::fd::{BorrowedFd, OwnedFd};
pub use crate::json::JsonVariant;
pub use crate::log::{
    LOG_ALERT, LOG_CRIT, LOG_DEBUG, LOG_EMERG, LOG_ERR, LOG_INFO, LOG_NOTICE, LOG_WARNING,
};
pub use crate::strv::Strv;
pub use crate::{
    command_print_help, command_print_help_name, command_print_verb_help, define_main,
    define_main_with_positive_failure, define_test_main, dispatch_verb, foreach_option, introspect_cli,
    print, println, verbs,
};
pub use crate::{
    log_debug, log_debug_errno, log_error, log_error_errno, log_full, log_full_errno, log_info,
    log_info_errno, log_notice, log_notice_errno, log_oom, log_warning, log_warning_errno,
};
