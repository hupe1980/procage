//! The ELF interpreter (`PT_INTERP`) of a program, read from the start of
//! its file.
//!
//! Under [`Exec::Never`](crate::Exec::Never) and
//! [`Exec::Program`](crate::Exec::Program) the Linux backend allows the
//! spawned program and the interpreter the kernel loads for it, which the
//! kernel opens for execution too. The program can be any file the caller
//! names, possibly written by an earlier run, so the reader trusts nothing:
//! every offset is checked against the bytes it was given, the number of
//! program headers and the length of the path are bounded, and no input
//! makes it panic (fuzz target `elf`).

use core::fmt;

/// `PT_INTERP`.
const PT_INTERP: u32 = 3;

/// The most program headers read.
pub const MAX_PROGRAM_HEADERS: usize = 64;

/// The longest interpreter path accepted, without its NUL (`PATH_MAX` - 1).
pub const MAX_INTERPRETER: usize = 4095;

/// Why an ELF file's interpreter cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ElfError {
    /// The header or the program headers lie beyond the bytes read.
    Truncated,
    /// More program headers than [`MAX_PROGRAM_HEADERS`], or entries too
    /// small to be program headers.
    BadProgramHeaders,
    /// The interpreter path is empty, too long, not NUL-terminated or
    /// contains a NUL.
    BadInterpreter,
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ElfError::Truncated => "unreadable program headers",
            ElfError::BadProgramHeaders => "malformed program headers",
            ElfError::BadInterpreter => "malformed interpreter path",
        })
    }
}

/// The interpreter path of the ELF file that starts with `file_start`, or
/// `None` for a statically linked ELF file or a file that is not ELF (the
/// kernel then loads no interpreter for it, or refuses it).
pub fn interpreter(file_start: &[u8]) -> Result<Option<&[u8]>, ElfError> {
    if file_start.len() < 16 || file_start[..4] != *b"\x7fELF" {
        return Ok(None);
    }
    let wide = match file_start[4] {
        1 => false,
        2 => true,
        _ => return Ok(None),
    };
    let big = match file_start[5] {
        1 => false,
        2 => true,
        _ => return Ok(None),
    };
    let read = Reader {
        bytes: file_start,
        big,
    };
    // e_phoff, e_phentsize, e_phnum.
    let (phoff, phentsize, phnum) = if wide {
        (read.u64(32)?, read.u16(54)?, read.u16(56)?)
    } else {
        (u64::from(read.u32(28)?), read.u16(42)?, read.u16(44)?)
    };
    let phnum = usize::from(phnum);
    let phentsize = usize::from(phentsize);
    let min_entry = if wide { 56 } else { 32 };
    if phnum > MAX_PROGRAM_HEADERS || (phnum > 0 && phentsize < min_entry) {
        return Err(ElfError::BadProgramHeaders);
    }
    let phoff = usize::try_from(phoff).map_err(|_| ElfError::Truncated)?;
    for i in 0..phnum {
        let entry = i
            .checked_mul(phentsize)
            .and_then(|o| o.checked_add(phoff))
            .ok_or(ElfError::Truncated)?;
        if read.u32(entry)? != PT_INTERP {
            continue;
        }
        // p_offset, p_filesz.
        let (offset, size) = if wide {
            (read.u64(entry + 8)?, read.u64(entry + 32)?)
        } else {
            (
                u64::from(read.u32(entry + 4)?),
                u64::from(read.u32(entry + 16)?),
            )
        };
        let start = usize::try_from(offset).map_err(|_| ElfError::Truncated)?;
        let size = usize::try_from(size).map_err(|_| ElfError::BadInterpreter)?;
        if !(2..=MAX_INTERPRETER + 1).contains(&size) {
            return Err(ElfError::BadInterpreter);
        }
        let end = start.checked_add(size).ok_or(ElfError::Truncated)?;
        let path = file_start.get(start..end).ok_or(ElfError::Truncated)?;
        let (nul, path) = path.split_last().ok_or(ElfError::BadInterpreter)?;
        if *nul != 0 || path.contains(&0) {
            return Err(ElfError::BadInterpreter);
        }
        return Ok(Some(path));
    }
    Ok(None)
}

struct Reader<'a> {
    bytes: &'a [u8],
    big: bool,
}

impl Reader<'_> {
    fn take<const N: usize>(&self, at: usize) -> Result<[u8; N], ElfError> {
        let end = at.checked_add(N).ok_or(ElfError::Truncated)?;
        let slice = self.bytes.get(at..end).ok_or(ElfError::Truncated)?;
        let mut out = [0; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn u16(&self, at: usize) -> Result<u16, ElfError> {
        let b = self.take::<2>(at)?;
        Ok(if self.big {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        })
    }

    fn u32(&self, at: usize) -> Result<u32, ElfError> {
        let b = self.take::<4>(at)?;
        Ok(if self.big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    }

    fn u64(&self, at: usize) -> Result<u64, ElfError> {
        let b = self.take::<8>(at)?;
        Ok(if self.big {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// A little-endian ELF64 file with `headers` program headers, the
    /// interpreter (if any) in the first, and the path after them.
    fn elf64(interp: Option<&[u8]>, headers: u16) -> Vec<u8> {
        let mut f = vec![0u8; 64];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 2;
        f[5] = 1;
        f[32..40].copy_from_slice(&64u64.to_le_bytes());
        f[54..56].copy_from_slice(&56u16.to_le_bytes());
        f[56..58].copy_from_slice(&headers.to_le_bytes());
        let path_at = 64 + 56 * usize::from(headers);
        f.resize(path_at, 0);
        if let Some(path) = interp {
            f[64..68].copy_from_slice(&PT_INTERP.to_le_bytes());
            f[72..80].copy_from_slice(&(path_at as u64).to_le_bytes());
            f[96..104].copy_from_slice(&(path.len() as u64 + 1).to_le_bytes());
            f.extend_from_slice(path);
            f.push(0);
        }
        f
    }

    /// A big-endian ELF32 file with the interpreter in its only header.
    fn elf32_be(path: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 52];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 1;
        f[5] = 2;
        f[28..32].copy_from_slice(&52u32.to_be_bytes());
        f[42..44].copy_from_slice(&32u16.to_be_bytes());
        f[44..46].copy_from_slice(&1u16.to_be_bytes());
        f.resize(84, 0);
        f[52..56].copy_from_slice(&PT_INTERP.to_be_bytes());
        f[56..60].copy_from_slice(&84u32.to_be_bytes());
        f[68..72].copy_from_slice(&(path.len() as u32 + 1).to_be_bytes());
        f.extend_from_slice(path);
        f.push(0);
        f
    }

    #[test]
    fn a_dynamic_program_names_its_interpreter() {
        let f = elf64(Some(b"/lib64/ld-linux-x86-64.so.2"), 3);
        assert_eq!(
            interpreter(&f),
            Ok(Some(&b"/lib64/ld-linux-x86-64.so.2"[..]))
        );
        let f = elf32_be(b"/lib/ld.so.1");
        assert_eq!(interpreter(&f), Ok(Some(&b"/lib/ld.so.1"[..])));
    }

    #[test]
    fn a_static_program_or_another_format_has_none() {
        assert_eq!(interpreter(&elf64(None, 2)), Ok(None));
        assert_eq!(interpreter(b"#!/bin/sh\n"), Ok(None));
        assert_eq!(interpreter(b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01"), Ok(None));
        assert_eq!(interpreter(b""), Ok(None));
    }

    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        let f = elf64(Some(b"/lib/ld.so"), 2);
        for len in 16..f.len() {
            let r = interpreter(&f[..len]);
            assert!(matches!(r, Err(ElfError::Truncated)), "{len}: {r:?}");
        }
    }

    #[test]
    fn bounds_hold() {
        let mut f = elf64(Some(b"/lib/ld.so"), 1);
        f[56..58].copy_from_slice(&65u16.to_le_bytes());
        assert_eq!(interpreter(&f), Err(ElfError::BadProgramHeaders));
        let mut f = elf64(Some(b"/lib/ld.so"), 1);
        f[54..56].copy_from_slice(&8u16.to_le_bytes());
        assert_eq!(interpreter(&f), Err(ElfError::BadProgramHeaders));
        let long = vec![b'a'; MAX_INTERPRETER + 1];
        assert_eq!(
            interpreter(&elf64(Some(&long), 1)),
            Err(ElfError::BadInterpreter)
        );
        let mut f = elf64(Some(b"/lib/ld.so"), 1);
        let n = f.len();
        f[n - 1] = b'x';
        assert_eq!(interpreter(&f), Err(ElfError::BadInterpreter));
        assert_eq!(
            interpreter(&elf64(Some(b"/li\0b"), 1)),
            Err(ElfError::BadInterpreter)
        );
        let mut f = elf64(Some(b"/lib/ld.so"), 1);
        f[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(interpreter(&f).is_err());
    }
}
