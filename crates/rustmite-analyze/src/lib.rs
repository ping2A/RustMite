//! Pure analysis helpers — no I/O.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

pub mod entropy;
pub mod elf;
pub mod hash;
pub mod shadow;
pub mod authorized_keys;
pub mod utmp;
pub mod passwd;
pub mod dpkg;

pub use entropy::{shannon_entropy, sliding_window_max};
pub use elf::{analyze_elf, ElfAnalysis};
pub use hash::{blake3_hex, md5_hex, sha256_hex};
pub use shadow::{parse_shadow, parse_shadow_line, ShadowParsed};
pub use authorized_keys::{parse_authorized_key_line, AuthorizedKeyParsed};
pub use utmp::{parse_utmp, UtmpRecord, UTMP_RECORD_SIZE};
pub use passwd::{parse_passwd, parse_passwd_line, PasswdEntry};
pub use dpkg::{
    is_critical_package_path, package_name_from_md5sums_filename, parse_md5sums,
    parse_md5sums_line, DpkgMd5Entry,
};
