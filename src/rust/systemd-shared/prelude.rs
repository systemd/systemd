// SPDX-License-Identifier: LGPL-2.1-or-later

//! `use systemd_shared::prelude::*;` brings in what every program needs, including the [`Box`] and [`Vec`]
//! that replace the ones of `alloc`.

pub use crate::alloc::{AllocError, Box, Vec};
pub use crate::cstr::OwnedCStr;
pub use crate::errno::{check, from_result, Errno, Result};
pub use crate::fd::{BorrowedFd, OwnedFd};
pub use crate::log::{
    LOG_ALERT, LOG_CRIT, LOG_DEBUG, LOG_EMERG, LOG_ERR, LOG_INFO, LOG_NOTICE, LOG_WARNING,
};
pub use crate::strv::Strv;
pub use crate::{
    log_debug, log_debug_errno, log_error, log_error_errno, log_full, log_full_errno, log_info,
    log_info_errno, log_notice, log_notice_errno, log_oom, log_warning, log_warning_errno,
};
pub use crate::{print, println};
