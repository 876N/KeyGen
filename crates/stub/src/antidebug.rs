#[cfg(windows)]
pub fn apply_environment_transform(key: &mut [u8; 32]) {
    use std::ffi::CString;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        CheckRemoteDebuggerPresent, IsDebuggerPresent,
    };
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let xor = |key: &mut [u8; 32], v: u8| {
        for b in key.iter_mut() {
            *b ^= v;
        }
    };

    unsafe {
        if IsDebuggerPresent() != 0 {
            xor(key, 0xCC);
        }
        let mut remote: i32 = 0;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut remote);
        if remote != 0 {
            xor(key, 0xAA);
        }

        if peb_being_debugged() {
            xor(key, 0xDE);
        }
        if peb_nt_global_flag_set() {
            xor(key, 0x33);
        }

        let ntdll_name = CString::new("ntdll.dll").unwrap();
        let h_ntdll = GetModuleHandleA(ntdll_name.as_ptr() as *const u8);
        if h_ntdll != 0 {
            let nq_name = CString::new("NtQueryInformationProcess").unwrap();
            let p = GetProcAddress(h_ntdll, nq_name.as_ptr() as *const u8);
            if let Some(addr) = p {
                type NQ = unsafe extern "system" fn(
                    isize,
                    u32,
                    *mut std::ffi::c_void,
                    u32,
                    *mut u32,
                ) -> i32;
                let f: NQ = std::mem::transmute(addr);
                let mut debug_port: usize = 0;
                let status = f(
                    GetCurrentProcess(),
                    7,
                    &mut debug_port as *mut usize as *mut std::ffi::c_void,
                    std::mem::size_of::<usize>() as u32,
                    std::ptr::null_mut(),
                );
                if status == 0 && debug_port != 0 {
                    xor(key, 0x55);
                }

                let mut debug_obj: usize = 0;
                let status = f(
                    GetCurrentProcess(),
                    30,
                    &mut debug_obj as *mut usize as *mut std::ffi::c_void,
                    std::mem::size_of::<usize>() as u32,
                    std::ptr::null_mut(),
                );
                if status == 0 && debug_obj != 0 {
                    xor(key, 0x77);
                }
            }
        }

        if has_hardware_breakpoints() {
            xor(key, 0xBB);
        }
    }
}

#[cfg(windows)]
unsafe fn peb_get() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let peb: usize;
        std::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nostack, preserves_flags, readonly),
        );
        peb
    }
    #[cfg(target_arch = "x86")]
    {
        let peb: usize;
        std::arch::asm!(
            "mov {}, fs:[0x30]",
            out(reg) peb,
            options(nostack, preserves_flags, readonly),
        );
        peb
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        0
    }
}

#[cfg(windows)]
unsafe fn peb_being_debugged() -> bool {
    let peb = peb_get();
    if peb == 0 {
        return false;
    }
    let p = peb as *const u8;
    std::ptr::read_volatile(p.add(0x02)) != 0
}

#[cfg(windows)]
unsafe fn peb_nt_global_flag_set() -> bool {
    let peb = peb_get();
    if peb == 0 {
        return false;
    }
    let p = peb as *const u8;
    #[cfg(target_arch = "x86_64")]
    let off = 0xBC;
    #[cfg(target_arch = "x86")]
    let off = 0x68;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    let off = 0;
    let flags = std::ptr::read_volatile(p.add(off) as *const u32);
    (flags & 0x70) != 0
}

#[cfg(windows)]
unsafe fn has_hardware_breakpoints() -> bool {
    use std::ffi::CString;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows_sys::Win32::System::Threading::GetCurrentThread;

    let kernel = CString::new("kernel32.dll").unwrap();
    let h = GetModuleHandleA(kernel.as_ptr() as *const u8);
    if h == 0 {
        return false;
    }
    let gtc = CString::new("GetThreadContext").unwrap();
    let p = match GetProcAddress(h, gtc.as_ptr() as *const u8) {
        Some(a) => a,
        None => return false,
    };

    #[cfg(target_arch = "x86_64")]
    {
        #[repr(C, align(16))]
        struct CtxX64 {
            _p: [u64; 6],
            context_flags: u32,
            _pad: [u32; 1],
            _segs_eflags: [u32; 4],
            dr0: u64,
            dr1: u64,
            dr2: u64,
            dr3: u64,
            dr6: u64,
            dr7: u64,
            _rest: [u8; 1024],
        }
        type GTC = unsafe extern "system" fn(isize, *mut CtxX64) -> i32;
        let f: GTC = std::mem::transmute(p);
        let mut ctx: CtxX64 = std::mem::zeroed();
        ctx.context_flags = 0x00100010;
        if f(GetCurrentThread(), &mut ctx) != 0 {
            return ctx.dr0 != 0 || ctx.dr1 != 0 || ctx.dr2 != 0 || ctx.dr3 != 0;
        }
    }
    #[cfg(target_arch = "x86")]
    {
        #[repr(C)]
        struct CtxX86 {
            context_flags: u32,
            dr0: u32,
            dr1: u32,
            dr2: u32,
            dr3: u32,
            dr6: u32,
            dr7: u32,
            _rest: [u8; 512],
        }
        type GTC = unsafe extern "system" fn(isize, *mut CtxX86) -> i32;
        let f: GTC = std::mem::transmute(p);
        let mut ctx: CtxX86 = std::mem::zeroed();
        ctx.context_flags = 0x00010010;
        if f(GetCurrentThread(), &mut ctx) != 0 {
            return ctx.dr0 != 0 || ctx.dr1 != 0 || ctx.dr2 != 0 || ctx.dr3 != 0;
        }
    }
    false
}

#[cfg(not(windows))]
pub fn apply_environment_transform(_key: &mut [u8; 32]) {}
