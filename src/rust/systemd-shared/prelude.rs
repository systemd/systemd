// SPDX-License-Identifier: LGPL-2.1-or-later

//! `use systemd_shared::prelude::*;` brings in what every program needs.

pub use crate::command::{version, Argv, OptionParser, VERB_ANY};
pub use crate::cstr::OwnedCStr;
pub use crate::errno::{check, from_result, Errno, Result};
pub use crate::event::{Event, EventSource};
pub use crate::json::JsonVariant;
pub use crate::strv::Strv;
pub use crate::{
    command_print_help, command_print_help_name, define_main, dispatch_verb, foreach_option, introspect_cli,
    verbs,
};
pub use crate::{
    log_debug, log_debug_errno, log_error, log_error_errno, log_full, log_full_errno, log_info,
    log_info_errno, log_notice, log_notice_errno, log_oom, log_warning, log_warning_errno,
};
