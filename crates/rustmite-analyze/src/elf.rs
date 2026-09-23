//! ELF analysis via goblin.

use goblin::elf::program_header;
use goblin::elf::Elf;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ElfAnalysis {
    pub is_elf: bool,
    pub machine: String,
    pub is_static: bool,
    pub stripped: bool,
    pub interp: Option<String>,
    pub section_count: u16,
    pub has_rwx_segment: bool,
    pub packer_hints: Vec<String>,
    pub entry: u64,
}

/// Analyse raw bytes as ELF. Non-ELF input returns `is_elf: false` without error.
pub fn analyze_elf(data: &[u8]) -> ElfAnalysis {
    if data.len() < 4 || data.get(0..4) != Some(&[0x7f, b'E', b'L', b'F']) {
        return ElfAnalysis::default();
    }

    let Ok(elf) = Elf::parse(data) else {
        return ElfAnalysis {
            is_elf: true,
            machine: String::from("unknown"),
            ..ElfAnalysis::default()
        };
    };

    let machine = machine_name(elf.header.e_machine);
    let section_count = elf.header.e_shnum;
    let stripped = elf.syms.is_empty() && section_count > 0;
    let is_static = elf.libraries.is_empty() && elf.interpreter.is_none();
    let interp = elf.interpreter.map(String::from);
    let entry = elf.entry;

    let mut has_rwx_segment = false;
    let mut packer_hints = Vec::new();

    for ph in &elf.program_headers {
        let flags = ph.p_flags;
        let r = (flags & program_header::PF_R) != 0;
        let w = (flags & program_header::PF_W) != 0;
        let x = (flags & program_header::PF_X) != 0;
        if r && w && x {
            has_rwx_segment = true;
            push_unique(&mut packer_hints, "rwx_segment");
        }
    }

    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            let upper = name.to_ascii_uppercase();
            if upper.contains("UPX") {
                push_unique(&mut packer_hints, "upx_section");
            }
        }
    }

    if section_count == 0 {
        push_unique(&mut packer_hints, "no_section_headers");
    } else if section_count < 3 {
        push_unique(&mut packer_hints, "few_sections");
    }

    if stripped {
        push_unique(&mut packer_hints, "stripped");
    }

    ElfAnalysis {
        is_elf: true,
        machine,
        is_static,
        stripped,
        interp,
        section_count,
        has_rwx_segment,
        packer_hints,
        entry,
    }
}

fn push_unique(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(String::from(s));
    }
}

fn machine_name(m: u16) -> String {
    let s = match m {
        3 => "i386",
        8 => "mips",
        20 => "ppc",
        21 => "ppc64",
        40 => "arm",
        62 => "x86_64",
        183 => "aarch64",
        243 => "riscv",
        _ => "unknown",
    };
    String::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_elf_magic() {
        let mut buf = vec![0u8; 64];
        if let Some(b) = buf.get_mut(0..4) {
            b.copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        }
        let a = analyze_elf(&buf);
        assert!(a.is_elf);
    }

    #[test]
    fn non_elf_is_false() {
        let a = analyze_elf(b"not an elf");
        assert!(!a.is_elf);
    }

    #[test]
    fn empty_is_false() {
        assert!(!analyze_elf(&[]).is_elf);
    }
}
