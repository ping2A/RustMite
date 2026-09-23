//! Raw Linux syscall + `/proc` primitives.
//!
//! Every collector takes `&dyn ProcSource` so rootkit detection is unit-testable
//! against recorded/synthetic trees without running rootkits.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod error;
pub mod dirent;
pub mod procfs;
pub mod fs;
pub mod parse;
pub mod pid_probe;

pub use error::{Errno, SysError};
pub use dirent::DirEnt;
pub use procfs::{FixtureProc, LiveProc, ProcSource, Statx};
pub use fs::{FixtureFs, FsSource, LiveFs};
pub use parse::{parse_cmdline, parse_proc_stat, parse_status_map, ProcStat};
pub use pid_probe::{PidLiveness, PidProbeView};
