use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub fn detect_pe_arch<P: AsRef<Path>>(file_path: P) -> i32 {
    let mut f = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let mut dos = [0u8; 64];
    if f.read_exact(&mut dos).is_err() {
        return 0;
    }
    if dos[0] != b'M' || dos[1] != b'Z' {
        return 0;
    }
    let pe_off = u32::from_le_bytes([dos[0x3C], dos[0x3D], dos[0x3E], dos[0x3F]]);
    if f.seek(SeekFrom::Start(pe_off as u64)).is_err() {
        return 0;
    }
    let mut pe_header = [0u8; 6];
    if f.read_exact(&mut pe_header).is_err() {
        return 0;
    }
    if pe_header[0] != b'P' || pe_header[1] != b'E' || pe_header[2] != 0 || pe_header[3] != 0 {
        return 0;
    }
    let machine = u16::from_le_bytes([pe_header[4], pe_header[5]]);
    match machine {
        0x014c => 32,
        0x8664 => 64,
        _ => 0,
    }
}

pub fn is_dotnet_file<P: AsRef<Path>>(file_path: P) -> bool {
    let mut f = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = [0u8; 512];
    let read = match f.read(&mut buf) {
        Ok(r) => r,
        Err(_) => return false,
    };
    if read < 512 {
        return false;
    }
    if buf[0] != b'M' || buf[1] != b'Z' {
        return false;
    }
    let pe_off =
        u32::from_le_bytes([buf[0x3C], buf[0x3D], buf[0x3E], buf[0x3F]]) as usize;
    if pe_off + 256 > 512 {
        return false;
    }
    let pe_sig = u32::from_le_bytes([
        buf[pe_off],
        buf[pe_off + 1],
        buf[pe_off + 2],
        buf[pe_off + 3],
    ]);
    if pe_sig != 0x00004550 {
        return false;
    }
    let magic =
        u16::from_le_bytes([buf[pe_off + 24], buf[pe_off + 25]]);
    let clr_dir_off = if magic == 0x10b {
        pe_off + 24 + 208
    } else if magic == 0x20b {
        pe_off + 24 + 224
    } else {
        return false;
    };
    if clr_dir_off + 8 > 512 {
        return false;
    }
    let clr_rva = u32::from_le_bytes([
        buf[clr_dir_off],
        buf[clr_dir_off + 1],
        buf[clr_dir_off + 2],
        buf[clr_dir_off + 3],
    ]);
    clr_rva != 0
}

pub fn arch_string(arch: i32) -> &'static str {
    match arch {
        32 => "32-bit (x86)",
        64 => "64-bit (x64)",
        _ => "Unknown",
    }
}
