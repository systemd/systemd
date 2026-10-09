// SPDX-License-Identifier: LGPL-2.1-or-later

//! Tables for humans and JSON, `format-table.h`.

use core::ffi::{c_int, c_void, CStr};
use core::ptr::{self, NonNull};

use crate::errno::{check, Errno, Result};
use crate::strv::Strv;
use crate::sys;

pub use sys::{TableErsatz, TABLE_ERSATZ_DASH, TABLE_ERSATZ_EMPTY, TABLE_ERSATZ_NA, TABLE_ERSATZ_UNSET};

/// A table, freed with `table_unref()`.
#[derive(Debug)]
pub struct Table(NonNull<sys::Table>);

impl Table {
    /// `table_new()`: a table with these column headers, at least one.
    pub fn new(headers: &[&CStr]) -> Result<Table> {
        if headers.is_empty() {
            return Err(Errno::EINVAL);
        }
        // SAFETY: plain call into libsystemd-shared.
        let t = NonNull::new(unsafe { sys::table_new_raw(headers.len()) }).ok_or(Errno::ENOMEM)?;
        let mut t = Table(t);
        for h in headers {
            // SAFETY: TABLE_HEADER takes a C string.
            unsafe { t.add(sys::TABLE_HEADER, h.as_ptr().cast()) }?;
        }
        Ok(t)
    }

    /// The raw pointer, for passing to C.
    pub fn as_ptr(&self) -> *mut sys::Table {
        self.0.as_ptr()
    }

    /// `table_add_cell()`.
    ///
    /// # Safety
    ///
    /// `data` must point to what `type_` takes, see `table_data_size()`.
    unsafe fn add(&mut self, type_: sys::TableDataType, data: *const c_void) -> Result<()> {
        // SAFETY: the caller passes data of the shape type_ requires, the cell takes a copy.
        check(unsafe { sys::table_add_cell(self.0.as_ptr(), ptr::null_mut(), type_, data) }).map(|_| ())
    }

    /// Adds a `TABLE_EMPTY` cell.
    pub fn add_empty(&mut self) -> Result<()> {
        // SAFETY: TABLE_EMPTY takes nothing.
        unsafe { self.add(sys::TABLE_EMPTY, ptr::null()) }
    }

    /// Adds a `TABLE_STRING` cell.
    pub fn add_string(&mut self, s: &CStr) -> Result<()> {
        // SAFETY: TABLE_STRING takes a C string.
        unsafe { self.add(sys::TABLE_STRING, s.as_ptr().cast()) }
    }

    /// Adds a `TABLE_STRV` cell.
    pub fn add_strv(&mut self, l: &Strv) -> Result<()> {
        // SAFETY: TABLE_STRV takes an strv.
        unsafe { self.add(sys::TABLE_STRV, l.as_ptr().cast()) }
    }

    /// Adds a `TABLE_BOOLEAN_CHECKMARK` cell.
    pub fn add_boolean_checkmark(&mut self, b: bool) -> Result<()> {
        // SAFETY: TABLE_BOOLEAN_CHECKMARK reads a bool.
        unsafe { self.add(sys::TABLE_BOOLEAN_CHECKMARK, ptr::from_ref(&b).cast()) }
    }

    /// Adds a `TABLE_TRISTATE` cell, `None` is shown as unset.
    pub fn add_tristate(&mut self, b: Option<bool>) -> Result<()> {
        let v: c_int = b.map_or(-1, c_int::from);
        // SAFETY: TABLE_TRISTATE reads an int.
        unsafe { self.add(sys::TABLE_TRISTATE, ptr::from_ref(&v).cast()) }
    }

    /// Adds a `TABLE_UINT64` cell.
    pub fn add_uint64(&mut self, v: u64) -> Result<()> {
        // SAFETY: TABLE_UINT64 reads a uint64_t.
        unsafe { self.add(sys::TABLE_UINT64, ptr::from_ref(&v).cast()) }
    }

    /// `table_set_ersatz_string()`: what empty cells show.
    pub fn set_ersatz_string(&mut self, ersatz: TableErsatz) {
        // SAFETY: plain call on a valid table.
        unsafe { sys::table_set_ersatz_string(self.0.as_ptr(), ersatz) }
    }

    /// `table_print_with_pager()`.
    pub fn print_with_pager(
        &self,
        json_format_flags: sys::sd_json_format_flags_t,
        pager_flags: sys::PagerFlags,
        show_header: bool,
    ) -> Result<()> {
        // SAFETY: plain call on a valid table.
        check(unsafe {
            sys::table_print_with_pager(self.0.as_ptr(), json_format_flags, pager_flags, show_header)
        })
        .map(|_| ())
    }
}

impl Drop for Table {
    fn drop(&mut self) {
        // SAFETY: we own the table.
        unsafe { sys::table_unref(self.0.as_ptr()) };
    }
}

/// `table_log_add_error()`: logs a failure to add cells and evaluates to the [`Errno`](crate::Errno).
#[macro_export]
macro_rules! table_log_add_error {
    ($error:expr) => {{
        let __e: $crate::errno::Errno = ::core::convert::From::from($error);
        $crate::log_error_errno!(__e, "Failed to add cells to table: {}", __e)
    }};
}
