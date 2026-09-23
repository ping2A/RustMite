//! Directory entry from raw getdents64-style listing.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEnt {
    pub ino: u64,
    pub name: Vec<u8>,
    pub file_type: u8,
}

impl DirEnt {
    pub const DT_UNKNOWN: u8 = 0;
    pub const DT_FIFO: u8 = 1;
    pub const DT_CHR: u8 = 2;
    pub const DT_DIR: u8 = 4;
    pub const DT_BLK: u8 = 6;
    pub const DT_REG: u8 = 8;
    pub const DT_LNK: u8 = 10;
    pub const DT_SOCK: u8 = 12;

    pub fn name_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.name)
    }

    pub fn is_dot_or_dotdot(&self) -> bool {
        self.name == b"." || self.name == b".."
    }
}
