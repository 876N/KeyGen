use std::sync::Mutex;

#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;

#[cfg(windows)]
static CONSOLE_HANDLE: Mutex<Option<HANDLE>> = Mutex::new(None);

#[cfg(windows)]
pub fn init_console_handle() {
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut g = CONSOLE_HANDLE.lock().unwrap();
        *g = Some(h);
    }
}

#[cfg(not(windows))]
pub fn init_console_handle() {}

#[cfg(windows)]
pub fn cls() {
    print_text("\x1b[2J\x1b[H", 7);
}

#[cfg(not(windows))]
pub fn cls() {
    use std::io::Write;
    print!("\x1b[2J\x1b[H");
    let _ = std::io::stdout().flush();
}

#[cfg(windows)]
pub fn set_color(color: u16) {
    use windows_sys::Win32::System::Console::SetConsoleTextAttribute;
    unsafe {
        let g = CONSOLE_HANDLE.lock().unwrap();
        if let Some(h) = *g {
            SetConsoleTextAttribute(h, color);
        }
    }
}

#[cfg(not(windows))]
pub fn set_color(_color: u16) {}

#[cfg(windows)]
pub fn print_text(text: &str, color: u16) {
    use windows_sys::Win32::System::Console::{SetConsoleTextAttribute, WriteConsoleA};
    let bytes = text.as_bytes();
    let g = CONSOLE_HANDLE.lock().unwrap();
    if let Some(h) = *g {
        unsafe {
            SetConsoleTextAttribute(h, color);
            let mut written: u32 = 0;
            WriteConsoleA(
                h,
                bytes.as_ptr() as *const std::ffi::c_void,
                bytes.len() as u32,
                &mut written,
                std::ptr::null(),
            );
        }
    }
}

#[cfg(not(windows))]
pub fn print_text(text: &str, _color: u16) {
    use std::io::Write;
    print!("{text}");
    let _ = std::io::stdout().flush();
}

pub fn print_line(text: &str, color: u16) {
    let line = format!("{text}\n");
    print_text(&line, color);
}

#[cfg(windows)]
pub fn read_line() -> String {
    use windows_sys::Win32::System::Console::{GetStdHandle, ReadConsoleA, STD_INPUT_HANDLE};
    unsafe {
        let h_in = GetStdHandle(STD_INPUT_HANDLE);
        let mut buf = [0u8; 512];
        let mut read: u32 = 0;
        ReadConsoleA(
            h_in,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            (buf.len() - 1) as u32,
            &mut read,
            std::ptr::null(),
        );
        let s = String::from_utf8_lossy(&buf[..read as usize]).into_owned();
        s.trim_end_matches(['\r', '\n']).to_string()
    }
}

#[cfg(not(windows))]
pub fn read_line() -> String {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut s = String::new();
    let _ = stdin.lock().read_line(&mut s);
    s.trim_end_matches(['\r', '\n']).to_string()
}

#[cfg(windows)]
pub fn sleep_ms(ms: u32) {
    use windows_sys::Win32::System::Threading::Sleep;
    unsafe {
        Sleep(ms);
    }
}

#[cfg(not(windows))]
pub fn sleep_ms(ms: u32) {
    std::thread::sleep(std::time::Duration::from_millis(ms as u64));
}
