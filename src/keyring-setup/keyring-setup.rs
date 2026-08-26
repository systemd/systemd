// SPDX-License-Identifier: LGPL-2.1-or-later

//! systemd-keyring-setup: enrolls the X.509 certificates of the VOA hierarchy into the kernel's trust
//! keyrings and seals them.

#![no_std]
#![no_main]

use core::ffi::{c_int, CStr};
use core::ptr;
use core::sync::atomic::Ordering;

use systemd_shared::chase::{self, CHASE_MAX_MODE, CHASE_MKDIR_0755, CHASE_SAFE};
use systemd_shared::conf_files::ConfFile;
use systemd_shared::cstr::{self, display};
use systemd_shared::fileio::{self, READ_FULL_FILE_FAIL_WHEN_LARGER, READ_FULL_FILE_VERIFY_REGULAR};
use systemd_shared::keyring::{self, KeySerial};
use systemd_shared::kmod::Kmod;
use systemd_shared::prelude::*;
use systemd_shared::recurse_dir::{self, RECURSE_DIR_IGNORE_DOT, RECURSE_DIR_SORT};
use systemd_shared::sys::COMMAND_EXPERIMENTAL;
use systemd_shared::table::{Table, TABLE_ERSATZ_DASH};
use systemd_shared::tmpfile::{LinkableTmpfile, LINK_TMPFILE_REPLACE};
use systemd_shared::voa::{self, Lookup};
use systemd_shared::x509::{self, Der, X509};
use systemd_shared::{creds, fd, json, sys};
use systemd_shared::{libcrypto_note, libkmod_note, log_openssl_errors, table_log_add_error};

static ARG_PAGER_FLAGS: AtomicPagerFlags = AtomicPagerFlags::new(0);

verbs! {
    COMMAND {
        names: "systemd-keyring-setup\0",
        abstract_: "Enroll certificates from the VOA hierarchy into the kernel's trust keyrings.",
        argspec: "[KEYRING…]\0",
        man_pages: "systemd-keyring-setup.service(8)\0",
        pager_flags: ARG_PAGER_FLAGS,
        flags: COMMAND_EXPERIMENTAL,
    },
}

/// The permission mask we are left with after we dropped SetAttr.
const KEYRING_PERM_SEALED: u32 =
    sys::KEY_POS_SEARCH | sys::KEY_USR_VIEW | sys::KEY_USR_READ | sys::KEY_USR_WRITE;

const CERTIFICATE_SIZE_MAX: usize = 1024 * 1024;

const CREDENTIAL_PREFIX: &str = "keyring-setup.";

/// Cap the number of possible OSes in both the exact and bare form. 64 OSes is plenty and we can always
/// increase.
const CREDENTIAL_OS_MAX: usize = 64;

struct KeyringSpec {
    name: &'static CStr,
    /// The VOA role its certificates come from.
    role: &'static CStr,
    /// The VOA context below the role.
    context: &'static CStr,
    /// The module the kernel's keyring_unsealed= parameter is scoped to, i.e. /sys/module/<param>/, None if
    /// the kernel never seals the keyring.
    param: Option<&'static CStr>,
    /// The keyring exists once this module is loaded.
    module: Option<&'static CStr>,
    /// Fixed KEY_SPEC_* ID, None if the keyring only goes by name.
    spec_id: Option<KeySerial>,
}

static KEYRING_SPECS: [KeyringSpec; 3] = [
    KeyringSpec {
        name: c".dm-verity",
        role: c"kernel-keyring",
        context: c"dm-verity",
        param: Some(c"dm_verity"),
        module: Some(c"dm_verity"),
        spec_id: None,
    },
    KeyringSpec {
        name: c".fs-verity",
        role: c"kernel-keyring",
        context: c"fs-verity",
        param: None,
        module: None,
        spec_id: None,
    },
    KeyringSpec {
        name: c".bpf",
        role: c"kernel-keyring",
        context: c"bpf",
        param: Some(c"bpf"),
        module: None,
        spec_id: Some(sys::KEY_SPEC_BPF_KEYRING),
    },
];

fn keyring_spec_from_name(name: &CStr) -> Option<&'static KeyringSpec> {
    KEYRING_SPECS.iter().find(|s| s.name == name)
}

/// What the command line asks for.
struct Args {
    keyrings: Vec<&'static KeyringSpec>,
    dry_run: bool,
    json_format_flags: sys::sd_json_format_flags_t,
}

impl Args {
    fn selected(&self, spec: &KeyringSpec) -> bool {
        self.keyrings.is_empty() || self.keyrings.iter().any(|s| ptr::eq(*s, spec))
    }
}

/// What a run amounts to, the exit status: a hard failure outweighs input that could not be used.
#[derive(Clone, Copy)]
enum Outcome {
    Success,
    DataError,
    Failed(Errno),
}

impl Outcome {
    fn data_error(&mut self) {
        if let Outcome::Success = self {
            *self = Outcome::DataError;
        }
    }

    fn fail(&mut self, e: Errno) {
        if !matches!(self, Outcome::Failed(_)) {
            *self = Outcome::Failed(e);
        }
    }
}

/// Keeps the first error, `RET_GATHER()`.
fn gather(ret: &mut Option<Errno>, r: Result<()>) {
    if let Err(e) = r {
        ret.get_or_insert(e);
    }
}

struct Certificate {
    path: OwnedCStr,
    der: Der,
    /// The ": <hex>" tail of the kernel's description.
    description_suffix: OwnedCStr,
    /// None until enrolled.
    serial: Option<KeySerial>,
}

/// A key linked into the keyring.
struct Member {
    serial: KeySerial,
    /// None if the key could not be described.
    description: Option<keyring::Description>,
}

struct Keyring {
    spec: &'static KeyringSpec,
    /// 0 while unknown.
    serial: KeySerial,
    /// None while unknown, a dry run cannot load the module providing it.
    exists: Option<bool>,
    /// The boot-time flag, None if unknown.
    kernel_unsealed: Option<bool>,
    certificates: Vec<Certificate>,
    /// As last read, None if they could not be read.
    members: Option<Vec<Member>>,
    sealed: bool,
    /// A certificate could not be used.
    data_error: bool,
    /// A hard error that does not stop the sealing.
    failed: Option<Errno>,
}

impl Keyring {
    fn new(spec: &'static KeyringSpec) -> Keyring {
        Keyring {
            spec,
            serial: 0,
            exists: None,
            kernel_unsealed: None,
            certificates: Vec::new(),
            members: None,
            sealed: false,
            data_error: false,
            failed: None,
        }
    }

    fn name(&self) -> impl core::fmt::Display + '_ {
        display(self.spec.name)
    }

    fn members(&self) -> &[Member] {
        self.members.as_deref().unwrap_or_default()
    }

    /// The certificates this run enrolled that are still in the keyring.
    fn n_enrolled(&self) -> usize {
        self.certificates.iter().filter(|c| c.serial.is_some()).count()
    }

    /// Reads the members along with their descriptions, they are unknown if that fails.
    fn read_members(&mut self) -> Result<()> {
        self.members = None;

        let serials = keyring::list(self.serial)?;
        let mut members = Vec::with_capacity(serials.len())?;
        for &serial in &serials {
            // A key that cannot be described still counts, it just matches nothing
            let description = keyring::describe_full(serial)
                .map_err(|e| {
                    log_debug_errno!(
                        e,
                        "Failed to describe key {} of keyring {}, ignoring: {e}",
                        serial,
                        self.name()
                    )
                })
                .ok();
            members.push(Member { serial, description })?;
        }

        self.members = Some(members);
        Ok(())
    }
}

/// The kernel describes a certificate as "<subject>: <hex>", with the subject key identifier or, lacking one,
/// the serial number as hex. Returns the ": <hex>" part, separator included.
fn certificate_description_suffix(x: &X509) -> Result<OwnedCStr> {
    let (id, serial) = match x.subject_key_id() {
        Some(id) => (id, false),
        None => (x.serial_number(), true),
    };

    // For a certificate with no subjectKeyIdentifier and a negative serial number certificate_is_enrolled()
    // will not be able to match the key the kernel created. So on every run we would readd the certificate.
    // And once the keyring is sealed this would also fail. While such certificates are forbidden per RFC 5280
    // they can still be created via openssl x509 -req -set_serial -1. For such certificates openssl stores a
    // negative V_ASN1_NEG_INTEGER plus the absolute value in ->data. Detect such certificates and reject them.
    if serial && id.type_() == sys::V_ASN1_NEG_INTEGER as c_int {
        return Err(Errno::EBADMSG);
    }

    let d = id.data();
    let Some(first) = d.first() else {
        return Err(Errno::EBADMSG);
    };

    // DER pads a serial with the top bit set with a zero byte, which the kernel keeps
    let pad = if serial && first & 0x80 != 0 { "00" } else { "" };

    cstr::try_format(format_args!(": {pad}{}", Hex(d)))
}

/// Lowercase hex, formatted without allocating.
struct Hex<'a>(&'a [u8]);

impl core::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// Returns true if the certificate was added, false if the same certificate was found before.
fn load_certificate(k: &mut Keyring, f: &ConfFile) -> Result<bool> {
    let path = f.original_path();

    let text = f
        .fd()
        .ok_or(Errno::EBADF)
        .and_then(|fd| {
            fileio::read_full_file_full(
                fd,
                None,
                u64::MAX,
                CERTIFICATE_SIZE_MAX,
                READ_FULL_FILE_FAIL_WHEN_LARGER | READ_FULL_FILE_VERIFY_REGULAR,
            )
        })
        .map_err(|e| log_warning_errno!(e, "Failed to read '{}', ignoring: {e}", display(path)))?;
    if text.is_empty() {
        return Err(log_warning_errno!(
            SYNTHETIC_ERRNO(EBADMSG),
            "'{}' is empty, ignoring.",
            display(path)
        ));
    }

    let (x, more) = X509::from_pem(&text)
        .map_err(|e| log_warning_errno!(e, "Failed to parse '{}', ignoring: {e}", display(path)))?;

    // Don't allow certificate bundles.
    if more {
        return Err(log_warning_errno!(
            SYNTHETIC_ERRNO(EINVAL),
            "'{}' contains more than one certificate, ignoring. Store one certificate per file, CA certificates below trust-anchor-{}/.",
            display(path),
            display(k.spec.role)
        ));
    }

    // The kernel takes DER
    let Some(der) = x.to_der() else {
        return Err(log_openssl_errors!(
            LOG_WARNING,
            "Failed to encode '{}', ignoring",
            display(path)
        ));
    };

    // Every copy of a verifier counts, but the same certificate is enrolled once
    if let Some(c) = k.certificates.iter().find(|c| *c.der == *der) {
        log_debug!(
            "'{}' is identical to '{}', skipping.",
            display(path),
            display(&c.path)
        );
        return Ok(false);
    }

    let description_suffix = certificate_description_suffix(&x).map_err(|e| {
        log_warning_errno!(
            e,
            "Failed to determine the description of '{}', ignoring: {e}",
            display(path)
        )
    })?;

    let path = OwnedCStr::try_from(path).map_err(|_| log_oom!())?;
    k.certificates
        .push(Certificate {
            path,
            der,
            description_suffix,
            serial: None,
        })
        .map_err(|_| log_oom!())?;

    Ok(true)
}

fn collect_certificates(k: &mut Keyring, root: BorrowedFd<'_>, os: &Strv) -> Result<()> {
    // Without an identifier there is nothing to look up, the failure was reported once already and the keyring
    // is still sealed
    if os.is_empty() {
        log_debug!("No OS identifier, collecting nothing for keyring {}.", k.name());
        return Ok(());
    }

    // Trust anchors and artifact verifiers end up in the same flat keyring, the kernel validates chains itself
    for mode in [voa::VOA_MODE_ARTIFACT_VERIFIER, voa::VOA_MODE_TRUST_ANCHOR] {
        let lookup = Lookup {
            os,
            role: k.spec.role,
            context: k.spec.context,
            mode,
            technology: voa::VOA_TECHNOLOGY_X509,
            suffix: voa::VOA_X509_CERTIFICATE_SUFFIX,
        };

        let files = voa::list_verifiers(root, &lookup, voa::VOA_WARN).map_err(|e| {
            log_error_errno!(
                e,
                "Failed to enumerate certificates for keyring {}: {e}",
                k.name()
            )
        })?;

        for f in files.iter() {
            match load_certificate(k, f) {
                Err(e @ Errno::ENOMEM) => return Err(e),
                Err(_) => k.data_error = true,
                Ok(_) => {}
            }
        }
    }

    Ok(())
}

/// /sys/module/<module>/ below root.
fn open_module_dir(root: BorrowedFd<'_>, module: &CStr) -> Result<OwnedFd> {
    let flags = (sys::O_PATH | sys::O_DIRECTORY | sys::O_CLOEXEC) as c_int;
    let modules = chase::chase_and_openat(root, root, c"/sys/module", 0, flags)?;
    chase::chase_and_openat(root, modules.as_fd(), module, 0, flags)
}

/// Returns true if the keyring exists and may be provisioned, false if there is nothing to do.
fn locate_keyring(
    k: &mut Keyring,
    root: BorrowedFd<'_>,
    kmod: Option<&Kmod>,
    dry_run: bool,
) -> Result<bool> {
    let mut module_loaded = true;

    // The keyring exists once the module is loaded. Like modprobe, libkmod applies the parameters from the
    // kernel command line.
    if let Some(module) = k.spec.module {
        if dry_run {
            // A dry run may not load the module and without it being loaded it has no way of figuring out whether
            // the required keyring exists.
            module_loaded = open_module_dir(root, module).is_ok();
        } else if let Some(kmod) = kmod {
            let _ = kmod.load_and_warn(module, false);
        }
    }

    let r = match k.spec.spec_id {
        // Kernels without the keyring do not know its ID
        Some(id) => keyring::resolve(id).map_err(|e| match e {
            Errno::EINVAL => Errno::ENOKEY,
            e => e,
        }),
        None => keyring::find_by_name_at(root, k.spec.name, 0),
    };
    k.serial = match r {
        Ok(serial) => serial,
        Err(e @ Errno::ENOKEY) => {
            // Without the module loaded the keyring cannot exist yet, a dry run cannot tell
            k.exists = module_loaded.then_some(false);

            if k.certificates.is_empty() {
                log_debug_errno!(e, "Keyring {} not found, nothing to do: {e}", k.name());
            } else {
                log_notice!(
                    "Keyring {} not found, {} certificate(s) cannot be enrolled.",
                    k.name(),
                    k.certificates.len()
                );
            }
            return Ok(false);
        }
        Err(e @ Errno::ENOTUNIQ) => {
            return Err(log_error_errno!(
                e,
                "More than one keyring named {}, refusing.",
                k.name()
            ));
        }
        Err(e @ Errno::ERFKILL) => {
            return Err(log_error_errno!(
                e,
                "Kernel keyrings are not accessible here, /proc/keys is masked."
            ));
        }
        Err(e) => return Err(log_error_errno!(e, "Failed to look up keyring {}: {e}", k.name())),
    };

    k.exists = Some(true);

    let perm = keyring::perm(k.serial)
        .map_err(|e| log_error_errno!(e, "Failed to read permissions of keyring {}: {e}", k.name()))?;

    // Restriction state is not observable only the permission mask is. So use that to figure out whether a
    // keyring is sealed.
    if perm == KEYRING_PERM_SEALED {
        log_debug!("Keyring {} is sealed already.", k.name());
        k.sealed = true;
    } else if perm & sys::KEY_USR_SETATTR == 0 {
        // If SetAttr is missing neither the permission mask nor the restrictions can be changed. We don't know
        // what to do with that. So fail.
        return Err(log_error_errno!(
            SYNTHETIC_ERRNO(EPERM),
            "Keyring {} has permission mask 0x{perm:08x} not set by us and SetAttr is gone, cannot repair it.",
            k.name()
        ));
    } else if perm & sys::KEY_USR_WRITE == 0 {
        return Err(log_error_errno!(
            SYNTHETIC_ERRNO(EPERM),
            "Keyring {} has an unexpected permission mask 0x{perm:08x}, not touching it.",
            k.name()
        ));
    }

    if let Err(e) = k.read_members() {
        log_debug_errno!(e, "Failed to read keyring {}, ignoring: {e}", k.name());
    }

    Ok(true)
}

/// Returns true if the keyring may be provisioned, false if the kernel sealed it at boot.
fn check_unsealed(k: &mut Keyring, root: BorrowedFd<'_>) -> bool {
    let Some(param) = k.spec.param else {
        return true;
    };

    let unsealed = open_module_dir(root, param)
        .and_then(|d| chase::chase_and_open_parent_at(root, d.as_fd(), c"parameters/keyring_unsealed", 0))
        .and_then(|(dir, name)| fileio::read_boolean_file_at(dir.as_fd(), &name));
    let unsealed = match unsealed {
        Ok(unsealed) => unsealed,
        Err(e) => {
            // A sealed keyring refuses additions, hence enrollment tells the state, and a keyring the kernel
            // sealed at boot is then sealed like any other
            log_debug_errno!(
                e,
                "Cannot read keyring_unsealed parameter of {}, ignoring: {e}",
                display(param)
            );
            return true;
        }
    };
    k.kernel_unsealed = Some(unsealed);

    if !unsealed {
        if k.certificates.is_empty() {
            log_debug!("Keyring {} was sealed at boot, nothing to do.", k.name());
        } else {
            log_notice!(
                "Keyring {} was sealed at boot, {} certificate(s) cannot be enrolled. Pass {}.keyring_unsealed=1 on the kernel command line to provision it.",
                k.name(),
                k.certificates.len(),
                display(param)
            );
        }

        return false;
    }

    if k.certificates.is_empty() {
        log_warning!(
            "Keyring {} was left unsealed at boot, but no certificates are configured for it.",
            k.name()
        );
    }

    true
}

fn certificate_is_enrolled(members: &[Member], c: &Certificate) -> bool {
    // For asymmetric keys the kernel creates a description of the form "<subject>: <id>" if the key is added
    // without a description. For other key types the description is whatever the creator of the key added.
    // Such descriptions must not count as a match.
    members.iter().any(|m| {
        m.description.as_ref().is_some_and(|d| {
            d.type_.as_cstr() == c"asymmetric"
                && d.description
                    .to_bytes()
                    .ends_with(c.description_suffix.as_cstr().to_bytes())
        })
    })
}

/// Drops only what this invocation enrolled, so the tool may be called multiple times without wasting anyone
/// else's keys.
fn unlink_enrolled(k: &mut Keyring) -> Result<()> {
    let mut r = None;

    for c in &mut k.certificates {
        let Some(serial) = c.serial else { continue };
        let q = match keyring::unlink_key(k.serial, serial) {
            // Superseded by a later certificate, the kernel dropped the link already
            Err(Errno::ENOENT | Errno::ENOKEY) => Ok(()),
            q => q,
        };
        if q.is_ok() {
            c.serial = None;
        }
        gather(&mut r, q);
    }

    match r {
        Some(e) => Err(log_error_errno!(
            e,
            "Failed to remove the enrolled keys from keyring {}: {e}",
            k.name()
        )),
        None => Ok(()),
    }
}

fn enroll_certificates(k: &mut Keyring) {
    let hint = k.spec.param.filter(|_| k.kernel_unsealed.is_none());

    // Not enrolled by this run, but sealed in with the rest. Under a seal the restriction vetted them.
    if !k.sealed {
        for m in k.members() {
            let description = m.description.as_ref().map(|d| &*d.description);
            log_warning!(
                "Keyring {} already held key {}{}{}, it is sealed in as well.",
                k.name(),
                m.serial,
                if description.is_some() { ": " } else { "" },
                display(description.unwrap_or_default())
            );
        }
    }

    // In reverse: on a colliding subject and key identifier the kernel replaces the key, so the copy from the
    // highest-priority load path and the most specific OS identifier is enrolled last and wins.
    for i in (0..k.certificates.len()).rev() {
        let c = &k.certificates[i];

        if certificate_is_enrolled(k.members(), c) {
            log_debug!(
                "'{}' is in keyring {} already, skipping.",
                display(&c.path),
                k.name()
            );
            continue;
        }

        let serial = match keyring::add_asymmetric(k.serial, None, &c.der) {
            Ok(serial) => serial,
            Err(Errno::EPERM) => {
                // Sealed by the kernel at boot. Nothing can be added, but the mask can still be dropped.
                match hint {
                    Some(param) => log_notice!(
                        "Keyring {} is sealed, cannot enroll '{}'. Pass {}.keyring_unsealed=1 on the kernel command line to provision it.",
                        k.name(),
                        display(&c.path),
                        display(param)
                    ),
                    None => log_notice!(
                        "Keyring {} is sealed, cannot enroll '{}'.",
                        k.name(),
                        display(&c.path)
                    ),
                }
                break;
            }
            Err(
                e
                @ (Errno::EACCES | Errno::EDQUOT | Errno::ENOMEM | Errno::EKEYREVOKED | Errno::EKEYEXPIRED),
            ) => {
                // The keyring itself is the problem, sealing it is all that is left. What went in so far is the
                // low-priority tail, it must not be sealed in alone.
                log_error_errno!(
                    e,
                    "Failed to enroll '{}' into keyring {}, giving up: {e}",
                    display(&c.path),
                    k.name()
                );
                gather(&mut k.failed, Err(e));
                let _ = unlink_enrolled(k);
                break;
            }
            Err(e) => {
                match e {
                    Errno::ENOKEY => log_warning_errno!(
                        e,
                        "Keyring {} is sealed and '{}' is not signed by a key enrolled in it: {e}",
                        k.name(),
                        display(&c.path)
                    ),
                    Errno::EKEYREJECTED => log_warning_errno!(
                        e,
                        "Kernel rejected certificate '{}' (blacklisted, or its signature does not verify): {e}",
                        display(&c.path)
                    ),
                    Errno::ENOPKG => log_warning_errno!(
                        e,
                        "Kernel does not support the public key algorithm of '{}': {e}",
                        display(&c.path)
                    ),
                    _ => log_warning_errno!(e, "Failed to enroll '{}': {e}", display(&c.path)),
                };

                k.data_error = true;
                continue;
            }
        };

        k.certificates[i].serial = Some(serial);

        let description = keyring::description(serial)
            .map_err(|e| log_debug_errno!(e, "Failed to describe enrolled key, ignoring: {e}"))
            .ok();

        log_info!(
            "Enrolled '{}' into keyring {}{}{}.",
            display(&k.certificates[i].path),
            k.name(),
            if description.is_some() { " as " } else { "" },
            display(description.as_deref().unwrap_or_default())
        );
    }

    // A certificate with the same subject and key identifier as a key in the keyring replaces it, which only
    // reading the members again reveals
    if let Err(e) = k.read_members() {
        log_debug_errno!(e, "Failed to read keyring {}, ignoring: {e}", k.name());
        return;
    }

    let members = k.members.as_deref().unwrap_or_default();
    for c in &mut k.certificates {
        if c.serial.is_some_and(|s| !members.iter().any(|m| m.serial == s)) {
            log_info!(
                "'{}' was superseded by a certificate of higher priority with the same subject and key identifier.",
                display(&c.path)
            );
            c.serial = None;
        }
    }
}

fn seal_keyring(k: &mut Keyring, root: BorrowedFd<'_>) -> Result<()> {
    // Sealing only allows certificates signed by a key already in the keyring to be added. Dropping SetAttr
    // makes the restriction and mask immutable. The read and write permissions have to stay so keys can still
    // be enrolled.
    if k.sealed {
        return Ok(());
    }

    // Needs the setattr permission that goes away below
    match keyring::restrict(k.serial, Some(c"asymmetric"), Some(c"key_or_keyring:0:chain")) {
        Ok(()) => {}
        Err(Errno::EEXIST) => {
            // Someone else already restricted this keyring.
            log_warning!("Keyring {} carries a restriction not installed by us.", k.name());
            k.data_error = true;
        }
        Err(e) => {
            // If we fail to enroll certificates drop every certificate we have enrolled in this invocation. We
            // don't drop anything else so this tool may be called multiple times without wasting anyone else's
            // keys.
            let q = unlink_enrolled(k);
            return Err(log_error_errno!(
                e,
                "Failed to restrict keyring {}, leaving it unsealed and writable{}: {e}",
                k.name(),
                if q.is_err() {
                    " with keys enrolled"
                } else {
                    ", the enrolled keys removed"
                }
            ));
        }
    }

    // Note that if we fail to restrict the keyring above we also skip permission changes. If we were to remove
    // permissions we would lose the ability to restrict the keyring completely.
    keyring::set_perm(k.serial, KEYRING_PERM_SEALED)
        .map_err(|e| log_error_errno!(e, "Failed to drop permissions of keyring {}: {e}", k.name()))?;

    k.sealed = true;

    match &k.members {
        Some(members) => log_info!(
            "Sealed keyring {} with {} key(s), {} enrolled now.",
            k.name(),
            members.len(),
            k.n_enrolled()
        ),
        None => log_info!("Sealed keyring {}, {} enrolled now.", k.name(), k.n_enrolled()),
    }

    // Unloading a kernel module may destroy the keyring and circumvent the security model. Warn about that.
    if let Some(module) = k.spec.module {
        let loadable = open_module_dir(root, module)
            .and_then(|d| chase::chase_and_accessat(root, d.as_fd(), c"refcnt", 0, sys::F_OK as c_int));
        if loadable.is_ok() {
            log_warning!(
                "Keyring {} belongs to the loadable {} module: unloading the module may discard the keyring and its seal, and reloading it creates one that can be provisioned again. Build {} into the kernel to keep the enrolled set for the lifetime of the kernel.",
                k.name(),
                display(module),
                display(module)
            );
        }
    }

    Ok(())
}

fn add_row(t: &mut Table, k: &Keyring, paths: &Strv) -> Result<()> {
    t.add_string(k.spec.name)?;
    t.add_string(k.spec.context)?;
    match k.exists {
        Some(exists) => t.add_boolean_checkmark(exists)?,
        None => t.add_empty()?,
    }
    t.add_tristate(k.kernel_unsealed)?;
    match &k.members {
        Some(members) => t.add_uint64(members.len() as u64)?,
        None => t.add_empty()?,
    }
    t.add_boolean_checkmark(k.sealed)?;
    t.add_strv(paths)
}

fn add_to_table(t: &mut Table, k: &Keyring) -> Result<()> {
    let mut paths = Strv::new();
    for c in &k.certificates {
        paths.push(&c.path).map_err(|_| log_oom!())?;
    }

    add_row(t, k, &paths).map_err(|e| table_log_add_error!(e))
}

/// Returns true if a certificate could not be used.
fn process_keyring(
    kmod: Option<&Kmod>,
    spec: &'static KeyringSpec,
    root: BorrowedFd<'_>,
    os: &Strv,
    t: Option<&mut Table>,
    args: &Args,
) -> Result<bool> {
    let mut k = Keyring::new(spec);

    // An error enumerating the certificates does not stop the sealing
    let r = collect_certificates(&mut k, root, os);
    gather(&mut k.failed, r);

    let mut r = locate_keyring(&mut k, root, kmod, args.dry_run);
    if matches!(r, Ok(true)) {
        r = Ok(check_unsealed(&mut k, root));
    }

    if args.dry_run {
        if matches!(r, Ok(true)) {
            let n = k
                .certificates
                .iter()
                .filter(|c| !certificate_is_enrolled(k.members(), c))
                .count();
            log_info!("Would enroll {} certificate(s) into keyring {}.", n, k.name());
        }

        if let Some(t) = t {
            let q = add_to_table(t, &k);
            if r.is_ok() {
                q?;
            }
        }
    } else if matches!(r, Ok(true)) {
        enroll_certificates(&mut k);
        r = seal_keyring(&mut k, root).map(|()| true);
    }

    r?;
    if let Some(e) = k.failed {
        return Err(e);
    }

    Ok(k.data_error)
}

/// Credentials are the way to hand a certificate to an initrd without rebuilding it. Following the
/// specification's advice for verifiers retrieved from elsewhere, they are placed into the ephemeral load path
/// as artifact verifiers. Hence, masking, merging and everything else applies to them like to any other file.
/// Returns false if the credential is not a single certificate.
fn materialize_credential(
    root: BorrowedFd<'_>,
    creds: BorrowedFd<'_>,
    cn: &CStr,
    spec: &KeyringSpec,
    name: &CStr,
    os: &Strv,
    dry_run: bool,
) -> Result<bool> {
    // The exact OS identifier suffices
    let os = os.iter().next().ok_or(Errno::EINVAL)?;
    let path = cstr::try_format(format_args!(
        "{}/{}/{}/{}/{}/{}{}",
        display(voa::VOA_EPHEMERAL_LOAD_PATH),
        display(os),
        display(spec.role),
        display(spec.context),
        display(voa::VOA_TECHNOLOGY_X509),
        display(name),
        display(voa::VOA_X509_CERTIFICATE_SUFFIX)
    ))
    .map_err(|_| log_oom!())?;

    if dry_run {
        log_info!("Would place credential '{}' at '{path}'.", display(cn));
        return Ok(true);
    }

    let contents = creds::read_credential_at(creds, cn)
        .map_err(|e| log_error_errno!(e, "Failed to read credential '{}': {e}", display(cn)))?;

    // Only the certificate goes into the world-readable hierarchy, not a private key that came along
    let x = match X509::from_pem(&contents) {
        Ok((x, false)) => x,
        Ok((_, true)) => {
            log_warning!(
                "Credential '{}' contains more than one certificate, ignoring.",
                display(cn)
            );
            return Ok(false);
        }
        Err(Errno::ENOMEM) => return Err(log_oom!()),
        Err(e) => {
            log_warning_errno!(e, "Failed to parse credential '{}', ignoring: {e}", display(cn));
            return Ok(false);
        }
    };
    let pem = x
        .to_pem()
        .map_err(|e| log_error_errno!(e, "Failed to encode credential '{}': {e}", display(cn)))?;

    let (dir, base) =
        chase::chase_and_open_parent_at(root, root, &path, CHASE_MKDIR_0755 | CHASE_SAFE | CHASE_MAX_MODE)
            .map_err(|e| log_error_errno!(e, "Failed to create the directory of '{path}': {e}"))?;

    let tmp = LinkableTmpfile::open_at(dir.as_fd(), &base, (sys::O_WRONLY | sys::O_CLOEXEC) as c_int)
        .map_err(|e| log_error_errno!(e, "Failed to create '{path}': {e}"))?;

    fd::loop_write(tmp.fd(), pem.as_cstr().to_bytes())
        .map_err(|e| log_error_errno!(e, "Failed to write '{path}': {e}"))?;

    fd::fchmod(tmp.fd(), 0o644)
        .map_err(|e| log_error_errno!(e, "Failed to set the mode of '{path}': {e}"))?;

    tmp.link(&base, LINK_TMPFILE_REPLACE)
        .map_err(|e| log_error_errno!(e, "Failed to link '{path}' into place: {e}"))?;

    log_debug!("Placed credential '{}' at '{path}'.", display(cn));
    Ok(true)
}

/// Returns true if a credential could not be used.
fn materialize_credentials(
    root: BorrowedFd<'_>,
    creds_dir: Result<BorrowedFd<'_>>,
    os: &Strv,
    args: &Args,
) -> Result<bool> {
    let creds_dir = match creds_dir {
        Ok(fd) => fd,
        Err(Errno::ENXIO) => return Ok(false),
        Err(e) => return Err(log_error_errno!(e, "Failed to open credentials directory: {e}")),
    };

    if os.is_empty() {
        log_warning!("There is no OS identifier to place credentials under, ignoring them.");
        return Ok(false);
    }

    let de = recurse_dir::readdir_all(creds_dir, RECURSE_DIR_SORT | RECURSE_DIR_IGNORE_DOT)
        .map_err(|e| log_error_errno!(e, "Failed to read credentials directory: {e}"))?;

    let mut ret = None;
    let mut data_error = false;
    for cn in de.names() {
        let Some(e) = cstr::strip_prefix(cn, CREDENTIAL_PREFIX.as_bytes()) else {
            continue;
        };
        if e == c"os" {
            continue;
        }

        // keyring-setup.<keyring>.<name>, the keyring without its leading dot
        let found = KEYRING_SPECS.iter().find_map(|s| {
            let name = cstr::strip_prefix(e, s.name.to_bytes().strip_prefix(b".")?)?;
            Some((s, cstr::strip_prefix(name, b".")?))
        });
        let Some((spec, name)) = found else {
            log_warning!(
                "Ignoring unrecognized credential '{}', expected {CREDENTIAL_PREFIX}<keyring>.<name>.",
                display(cn)
            );
            continue;
        };
        if !voa::identifier_is_valid(name, false) {
            log_warning!(
                "Ignoring credential '{}', the name must consist of lowercase letters, digits, '.', '_' and '-'.",
                display(cn)
            );
            continue;
        }
        if !args.selected(spec) {
            log_debug!(
                "Skipping credential '{}', keyring {} is not selected.",
                display(cn),
                display(spec.name)
            );
            continue;
        }

        match materialize_credential(root, creds_dir, cn, spec, name, os, args.dry_run) {
            Ok(placed) => data_error |= !placed,
            Err(e) => gather(&mut ret, Err(e)),
        }
    }

    ret.map_or(Ok(data_error), Err)
}

/// Returns the identifiers if the credential exists.
fn os_from_credential(creds_dir: Result<BorrowedFd<'_>>) -> Result<Option<Strv>> {
    let v = match creds_dir.and_then(|d| creds::read_credential_string_at(d, c"keyring-setup.os")) {
        Ok(v) => v,
        Err(Errno::ENXIO | Errno::ENOENT) => return Ok(None),
        Err(e) => {
            return Err(log_warning_errno!(
                e,
                "Failed to read credential {CREDENTIAL_PREFIX}os, ignoring: {e}"
            ));
        }
    };

    let l = Strv::split(v.as_cstr(), sys::WHITESPACE, sys::EXTRACT_RETAIN_ESCAPE).map_err(|_| log_oom!())?;
    if l.is_empty() {
        return Err(log_warning_errno!(
            SYNTHETIC_ERRNO(EINVAL),
            "Credential {CREDENTIAL_PREFIX}os is empty, ignoring."
        ));
    }
    if l.len() > CREDENTIAL_OS_MAX {
        return Err(log_warning_errno!(
            SYNTHETIC_ERRNO(EINVAL),
            "Credential {CREDENTIAL_PREFIX}os lists more than {CREDENTIAL_OS_MAX} OS identifiers, ignoring it."
        ));
    }

    if let Some(i) = l.iter().find(|i| !voa::os_is_valid(i)) {
        return Err(log_warning_errno!(
            SYNTHETIC_ERRNO(EINVAL),
            "Invalid OS identifier '{}' in credential {CREDENTIAL_PREFIX}os, ignoring it.",
            display(i)
        ));
    }

    Ok(Some(l))
}

fn parse_argv(opts: &mut OptionParser<'_>, args: &mut Args) -> Result<c_int> {
    foreach_option! { opts,
        OPTION_COMMON_HELP => return command_print_help!(),
        OPTION_COMMON_VERSION => return version(),
        OPTION_LONG("dry-run", None, "Only show what would be enrolled") => args.dry_run = true,
        OPTION_COMMON_NO_PAGER => {
            ARG_PAGER_FLAGS.fetch_or(sys::PAGER_DISABLE, Ordering::Relaxed);
        },
        OPTION_COMMON_JSON => {
            let r = json::parse_argument(opts.arg(), &mut args.json_format_flags)?;
            if r <= 0 {
                return Ok(r);
            }
        },
        OPTION_COMMON_INTROSPECT_CLI => return introspect_cli!(sys::SD_JSON_FORMAT_OFF),
    }

    for a in opts.args().iter() {
        let Some(spec) = keyring_spec_from_name(a) else {
            return Err(log_error_errno!(
                SYNTHETIC_ERRNO(EINVAL),
                "Unknown keyring: '{}'",
                display(a)
            ));
        };
        args.keyrings.push(spec).map_err(|_| log_oom!())?;
    }

    if json::format_enabled(args.json_format_flags) && !args.dry_run {
        return Err(log_error_errno!(
            SYNTHETIC_ERRNO(EINVAL),
            "--json= is only supported together with --dry-run."
        ));
    }

    Ok(1)
}

fn run(argv: Argv<'_>) -> Result<c_int> {
    let mut args = Args {
        keyrings: Vec::new(),
        dry_run: false,
        json_format_flags: sys::SD_JSON_FORMAT_OFF,
    };

    let mut opts = OptionParser::new(argv);
    if parse_argv(&mut opts, &mut args)? <= 0 {
        return Ok(0);
    }

    libcrypto_note!(required);
    x509::dlopen_libcrypto(LOG_ERR)?;

    libkmod_note!(recommended);
    #[cfg(HAVE_KMOD)]
    let kmod = Kmod::setup()
        .map_err(|e| log_debug_errno!(e, "Failed to initialize libkmod, not loading kernel modules: {e}"))
        .ok();
    #[cfg(not(HAVE_KMOD))]
    let kmod: Option<Kmod> = None;

    let root = fd::reopen(
        BorrowedFd::XAT_FDROOT,
        (sys::O_PATH | sys::O_DIRECTORY | sys::O_CLOEXEC) as c_int,
    )
    .map_err(|e| log_error_errno!(e, "Failed to open root directory: {e}"))?;

    let mut outcome = Outcome::Success;

    // Its users treat its absence differently
    let creds = creds::open_credentials_dir_at(root.as_fd());
    let creds_dir = creds.as_ref().map(OwnedFd::as_fd).map_err(|&e| e);

    let os = match os_from_credential(creds_dir) {
        Ok(Some(l)) => l,
        r => {
            if r.is_err() {
                // Bad input, but os-release is still there
                outcome.data_error();
            }
            match voa::os_identifiers(root.as_fd()) {
                Ok((l, bare)) => {
                    if bare {
                        log_warning!(
                            "os-release contains characters the VOA specification does not permit, looking up the bare ID only. Pass the {CREDENTIAL_PREFIX}os credential to specify identifiers explicitly."
                        );
                    }
                    l
                }
                Err(e) => {
                    outcome.fail(log_error_errno!(
                        e,
                        "Failed to determine the OS identifier from os-release, enrolling nothing: {e}"
                    ));
                    Strv::new()
                }
            }
        }
    };

    // Sealing does not depend on it either
    match materialize_credentials(root.as_fd(), creds_dir, &os, &args) {
        Ok(true) => outcome.data_error(),
        Ok(false) => {}
        Err(e) => outcome.fail(e),
    }

    let mut t = if args.dry_run {
        let mut t = Table::new(&[
            c"keyring",
            c"context",
            c"exists",
            c"kernel unsealed",
            c"keys",
            c"sealed",
            c"certificates",
        ])
        .map_err(|_| log_oom!())?;
        t.set_ersatz_string(TABLE_ERSATZ_DASH);
        Some(t)
    } else {
        None
    };

    for spec in KEYRING_SPECS.iter().filter(|s| args.selected(s)) {
        match process_keyring(kmod.as_ref(), spec, root.as_fd(), &os, t.as_mut(), &args) {
            Ok(true) => outcome.data_error(),
            Ok(false) => {}
            Err(e) => outcome.fail(e),
        }
    }

    if let Some(t) = &t {
        t.print_with_pager(
            args.json_format_flags,
            ARG_PAGER_FLAGS.load(Ordering::Relaxed),
            true,
        )?;
    }

    match outcome {
        Outcome::Success => Ok(0),
        Outcome::DataError => Ok(sys::EX_DATAERR as c_int),
        Outcome::Failed(e) => Err(e),
    }
}

define_main_with_positive_failure!(run);
