use kg_shared::sha1;

#[cfg(windows)]
#[allow(non_snake_case)]
extern "system" {
    fn GetSystemDirectoryA(lpBuffer: *mut u8, uSize: u32) -> u32;
    fn GetVolumeInformationA(
        lpRootPathName: *const u8,
        lpVolumeNameBuffer: *mut u8,
        nVolumeNameSize: u32,
        lpVolumeSerialNumber: *mut u32,
        lpMaximumComponentLength: *mut u32,
        lpFileSystemFlags: *mut u32,
        lpFileSystemNameBuffer: *mut u8,
        nFileSystemNameSize: u32,
    ) -> i32;
    fn GetComputerNameA(lpBuffer: *mut u8, nSize: *mut u32) -> i32;
}

#[cfg(windows)]
pub fn get_hwid() -> String {
    let mut info: [u32; 4] = [0; 4];
    cpuid_leaf1(&mut info);

    let mut sys_dir = [0u8; 260];
    let mut vol_serial: u32 = 0;
    unsafe {
        GetSystemDirectoryA(sys_dir.as_mut_ptr(), sys_dir.len() as u32);
    }
    let mut root_drive = [0u8; 4];
    root_drive[0] = sys_dir[0];
    root_drive[1] = b':';
    root_drive[2] = b'\\';
    root_drive[3] = 0;
    unsafe {
        GetVolumeInformationA(
            root_drive.as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut vol_serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        );
    }

    let mut comp_name = [0u8; 256];
    let mut comp_len: u32 = 255;
    unsafe {
        GetComputerNameA(comp_name.as_mut_ptr(), &mut comp_len);
    }

    let mut buf: Vec<u8> = Vec::with_capacity(320);
    for v in &info {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    buf.extend_from_slice(&vol_serial.to_le_bytes());
    buf.extend_from_slice(&comp_name[..comp_len as usize]);

    let hash = sha1(&buf);
    format!(
        "{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}",
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]
    )
}

#[cfg(all(windows, target_arch = "x86_64"))]
#[allow(unused_unsafe)]
fn cpuid_leaf1(out: &mut [u32; 4]) {
    use std::arch::x86_64::__cpuid;
    let r = unsafe { __cpuid(1) };
    out[0] = r.eax;
    out[1] = r.ebx;
    out[2] = r.ecx;
    out[3] = r.edx;
}

#[cfg(all(windows, target_arch = "x86"))]
#[allow(unused_unsafe)]
fn cpuid_leaf1(out: &mut [u32; 4]) {
    use std::arch::x86::__cpuid;
    let r = unsafe { __cpuid(1) };
    out[0] = r.eax;
    out[1] = r.ebx;
    out[2] = r.ecx;
    out[3] = r.edx;
}

#[cfg(all(windows, not(any(target_arch = "x86", target_arch = "x86_64"))))]
fn cpuid_leaf1(out: &mut [u32; 4]) {
    out.fill(0);
}

#[cfg(not(windows))]
pub fn get_hwid() -> String {
    "0000-0000-0000-0000".to_string()
}
