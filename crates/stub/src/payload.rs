use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::cfg;

#[cfg(windows)]
pub fn get_exe_path() -> String {
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameA;
    let mut buf = [0u8; 260];
    unsafe {
        GetModuleFileNameA(0, buf.as_mut_ptr(), buf.len() as u32);
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

#[cfg(not(windows))]
pub fn get_exe_path() -> String {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub fn load_payload() -> Option<Vec<u8>> {
    let exe = get_exe_path();
    let payload_size = cfg::get_payload_size() as u64;
    if payload_size == 0 {
        return None;
    }
    let mut f = File::open(&exe).ok()?;
    let file_size = f.seek(SeekFrom::End(0)).ok()?;
    if file_size <= payload_size {
        return None;
    }
    let payload_start = file_size - payload_size;
    f.seek(SeekFrom::Start(payload_start)).ok()?;
    let mut data = vec![0u8; payload_size as usize];
    f.read_exact(&mut data).ok()?;
    Some(data)
}
