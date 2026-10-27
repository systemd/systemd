// SPDX-License-Identifier: LGPL-2.1-or-later

//! `.note.dlopen` ELF notes, `sd-dlopen.h`: which libraries a program may `dlopen()`, for packaging tools.

use crate::sys;

/// One ELF note: the header, the vendor name, and the JSON payload padded to four bytes.
#[doc(hidden)]
#[repr(C, align(4))]
pub struct Note<const N: usize> {
    namesz: u32,
    descsz: u32,
    type_: u32,
    name: [u8; 4],
    desc: [u8; N],
}

/// The size of the padded payload of a note carrying `json`.
#[doc(hidden)]
pub const fn __payload_size(json: &str) -> usize {
    (json.len() + 1).next_multiple_of(4)
}

/// The note carrying `json`, as `SD_ELF_NOTE_DLOPEN()` lays it out.
#[doc(hidden)]
pub const fn __note<const N: usize>(json: &str) -> Note<N> {
    let b = json.as_bytes();
    assert!(b.len() < N);
    let mut desc = [0; N];
    let mut i = 0;
    while i < b.len() {
        desc[i] = b[i];
        i += 1;
    }
    Note {
        namesz: 4,
        descsz: b.len() as u32 + 1,
        type_: sys::SD_ELF_NOTE_DLOPEN_TYPE,
        name: *b"FDO\0",
        desc,
    }
}

/// The priority of a dlopen dependency, checked like `_DLOPEN_CHECK_PRIORITY_*` does in C.
#[doc(hidden)]
#[macro_export]
macro_rules! __dlopen_priority {
    (required) => {
        "required"
    };
    (recommended) => {
        "recommended"
    };
    (suggested) => {
        "suggested"
    };
}

/// `ELF_NOTE_DLOPEN_ANCHORED(feature, description, priority, soname...)`: declares that the program may
/// `dlopen()` one of the sonames. Used where the library is loaded, so that the note is kept for as long
/// as the function using it is.
#[macro_export]
macro_rules! elf_note_dlopen {
    ($feature:ident, $description:literal, $priority:ident, $soname:literal $(, $more:literal)* $(,)?) => {{
        const __JSON: &str = ::core::concat!(
            "[{\"feature\":\"",
            ::core::stringify!($feature),
            "\",\"description\":\"",
            $description,
            "\",\"priority\":\"",
            $crate::__dlopen_priority!($priority),
            "\",\"soname\":[\"",
            $soname,
            "\""
            $(, ",\"", $more, "\"")*,
            "]}]"
        );
        #[used]
        #[link_section = ".note.dlopen"]
        static __NOTE: $crate::dlopen::Note<{ $crate::dlopen::__payload_size(__JSON) }> =
            $crate::dlopen::__note(__JSON);
        ::core::hint::black_box(&__NOTE);
    }};
}

/// `LIBCRYPTO_NOTE(priority)`.
#[macro_export]
macro_rules! libcrypto_note {
    ($priority:ident) => {
        #[cfg(HAVE_OPENSSL)]
        $crate::elf_note_dlopen!(
            libcrypto,
            "Support for cryptographic operations",
            $priority,
            "libcrypto.so.4",
            "libcrypto.so.3"
        );
    };
}

/// `LIBKMOD_NOTE(priority)`.
#[macro_export]
macro_rules! libkmod_note {
    ($priority:ident) => {
        #[cfg(HAVE_KMOD)]
        $crate::elf_note_dlopen!(
            kmod,
            "Support for loading kernel modules",
            $priority,
            "libkmod.so.2"
        );
    };
}
